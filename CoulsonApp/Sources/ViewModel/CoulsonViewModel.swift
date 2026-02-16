import Foundation
import SwiftUI

@MainActor
final class CoulsonViewModel: ObservableObject {
    @Published var apps: [AppRecord] = []
    @Published var warnings: ScanWarningsFile?
    @Published var isHealthy = false
    @Published var namedTunnelDomain: String?
    @Published var globalTunnelConnected = false
    @Published var globalTunnelConfigured = false
    @Published var globalTunnelCnameTarget: String?
    @Published var errorMessage: String?

    let client: UDSControlClient
    let domainSuffix: String
    @Published var proxyPort: Int?
    @Published var httpsPort: Int?
    let daemonManager: DaemonManager
    private var autoRefreshTask: Task<Void, Never>?

    init() {
        let socket = ProcessInfo.processInfo.environment["COULSON_CONTROL_SOCKET"]
            ?? "/tmp/coulson/coulson.sock"
        self.client = UDSControlClient(socketPath: socket)
        self.domainSuffix = ProcessInfo.processInfo.environment["COULSON_DOMAIN_SUFFIX"]
            ?? "coulson.local"
        if let listen = ProcessInfo.processInfo.environment["COULSON_LISTEN_HTTP"],
           let portStr = listen.split(separator: ":").last,
           let port = Int(portStr) {
            self.proxyPort = port
        } else {
            self.proxyPort = nil
        }
        self.daemonManager = DaemonManager(client: client)
    }

    func tunnelURL(for app: AppRecord) -> String? {
        guard app.tunnelMode != "none", let tunnelDomain = namedTunnelDomain else { return nil }
        let dotSuffix = ".\(domainSuffix)"
        let prefix = app.domain.hasSuffix(dotSuffix)
            ? String(app.domain.dropLast(dotSuffix.count))
            : app.domain
        return "https://\(prefix).\(tunnelDomain)"
    }

    func globalTunnelURL(for app: AppRecord) -> String? {
        guard globalTunnelConnected, let tunnelDomain = namedTunnelDomain else { return nil }
        let dotSuffix = ".\(domainSuffix)"
        let prefix = app.domain.hasSuffix(dotSuffix)
            ? String(app.domain.dropLast(dotSuffix.count))
            : app.domain
        return "https://\(prefix).\(tunnelDomain)"
    }

    // MARK: - Computed

    var subtitle: String {
        let running = apps.filter(\.enabled).count
        return isHealthy ? "\(running)/\(apps.count) running" : "daemon offline"
    }

    var warningLines: [String] {
        guard let scan = warnings?.scan else { return [] }
        return (scan.conflictDomains + scan.parseWarnings).prefix(8).map { $0 }
    }

    var warningSummary: String {
        guard let scan = warnings?.scan else { return "No warnings file yet." }
        return scan.hasIssues ? "\(scan.warningCount) warnings" : "No issues detected."
    }

    var sortedApps: [AppRecord] {
        apps.sorted { $0.name < $1.name }
    }

    // MARK: - Auto Refresh

    func startAutoRefresh() async {
        if autoRefreshTask != nil { return }
        autoRefreshTask = Task { [weak self] in
            guard let self else { return }
            await self.refreshAll()
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 1_500_000_000)
                await self.refreshAll()
            }
        }
    }

    func stopAutoRefresh() {
        autoRefreshTask?.cancel()
        autoRefreshTask = nil
    }

    // MARK: - Data Fetching

    func refreshAll() async {
        async let a: Void = refreshApps()
        async let w: Void = refreshWarnings()
        async let h: Void = refreshHealth()
        async let t: Void = refreshNamedTunnel()
        _ = await (a, w, h, t)
    }

    func refreshApps() async {
        do {
            let response = try client.request(method: "app.list", params: [:])
            let data = try JSONSerialization.data(withJSONObject: response, options: [])
            let parsed = try JSONDecoder().decode(AppListResponse.self, from: data)
            apps = parsed.apps
        } catch {
            apps = []
        }
    }

    func refreshWarnings() async {
        do {
            let response = try client.request(method: "apps.warnings", params: [:])
            let data = try JSONSerialization.data(withJSONObject: response, options: [])
            let parsed = try JSONDecoder().decode(WarningsResponse.self, from: data)
            warnings = parsed.warnings
        } catch {
            warnings = nil
        }
    }

    func refreshHealth() async {
        do {
            let result = try client.request(method: "health.ping", params: [:])
            isHealthy = true
            daemonManager.updateFromPing(version: result["version"] as? String)
            if let port = result["http_port"] as? Int {
                proxyPort = port
            }
            if let port = result["https_port"] as? Int {
                httpsPort = port
            }
        } catch {
            isHealthy = false
            daemonManager.updateFromPing(version: nil)
        }
    }

    func refreshNamedTunnel() async {
        do {
            let response = try client.request(method: "named_tunnel.status", params: [:])
            let connected = response["connected"] as? Bool ?? false
            let configured = response["configured"] as? Bool ?? connected
            globalTunnelConnected = connected
            globalTunnelConfigured = configured
            globalTunnelCnameTarget = response["cname_target"] as? String
            if let domain = response["domain"] as? String {
                namedTunnelDomain = domain
            } else {
                namedTunnelDomain = nil
            }
        } catch {
            globalTunnelConnected = false
            globalTunnelConfigured = false
            globalTunnelCnameTarget = nil
            namedTunnelDomain = nil
        }
    }

    // MARK: - Actions

    func setEnabled(app: AppRecord, enabled: Bool) async {
        let method = enabled ? "app.start" : "app.stop"
        do {
            _ = try client.request(method: method, params: ["app_id": app.id])
            await refreshAll()
        } catch {
            errorMessage = error.localizedDescription
            await refreshAll()
        }
    }

    func updateApp(app: AppRecord, params: [String: Any]) async {
        var allParams: [String: Any] = ["app_id": app.id]
        for (k, v) in params { allParams[k] = v }
        do {
            _ = try client.request(method: "app.update", params: allParams)
            await refreshAll()
        } catch {
            errorMessage = error.localizedDescription
            await refreshAll()
        }
    }

    func deleteApp(_ app: AppRecord) async -> Bool {
        do {
            _ = try client.request(method: "app.delete", params: ["app_id": app.id])
            await refreshAll()
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    func connectGlobalTunnel(token: String, domain: String) async {
        do {
            _ = try client.request(method: "named_tunnel.connect", params: [
                "token": token,
                "domain": domain,
            ])
            await refreshNamedTunnel()
        } catch {
            errorMessage = error.localizedDescription
            await refreshNamedTunnel()
        }
    }

    func disconnectGlobalTunnel() async {
        do {
            _ = try client.request(method: "named_tunnel.disconnect", params: [:])
            await refreshNamedTunnel()
        } catch {
            errorMessage = error.localizedDescription
            await refreshNamedTunnel()
        }
    }

    func reconnectGlobalTunnel() async {
        do {
            _ = try client.request(method: "named_tunnel.connect", params: [:])
            await refreshNamedTunnel()
        } catch {
            errorMessage = error.localizedDescription
            await refreshNamedTunnel()
        }
    }

    func createApp(params: [String: Any]) async -> Bool {
        do {
            _ = try client.request(method: "app.create", params: params)
            await refreshAll()
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    func app(byId id: Int) -> AppRecord? {
        apps.first { $0.id == id }
    }
}
