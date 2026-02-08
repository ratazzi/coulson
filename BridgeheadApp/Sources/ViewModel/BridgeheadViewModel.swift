import Foundation
import SwiftUI

@MainActor
final class BridgeheadViewModel: ObservableObject {
    @Published var apps: [AppRecord] = []
    @Published var warnings: ScanWarningsFile?
    @Published var isHealthy = false
    @Published var namedTunnelDomain: String?

    private let client: UDSControlClient
    let domainSuffix: String
    let proxyPort: Int?
    private var autoRefreshTask: Task<Void, Never>?

    init() {
        let socket = ProcessInfo.processInfo.environment["BRIDGEHEAD_CONTROL_SOCKET"]
            ?? "/tmp/bridgehead/bridgeheadd.sock"
        self.client = UDSControlClient(socketPath: socket)
        self.domainSuffix = ProcessInfo.processInfo.environment["BRIDGEHEAD_DOMAIN_SUFFIX"]
            ?? "bridgehead.local"
        if let listen = ProcessInfo.processInfo.environment["BRIDGEHEAD_LISTEN_HTTP"],
           let portStr = listen.split(separator: ":").last,
           let port = Int(portStr) {
            self.proxyPort = port
        } else {
            self.proxyPort = 80
        }
    }

    func tunnelURL(for app: AppRecord) -> String? {
        guard app.tunnelExposed, let tunnelDomain = namedTunnelDomain else { return nil }
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
        apps.sorted { lhs, rhs in
            if lhs.enabled != rhs.enabled { return lhs.enabled }
            return lhs.domain < rhs.domain
        }
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
            _ = try client.request(method: "health.ping", params: [:])
            isHealthy = true
        } catch {
            isHealthy = false
        }
    }

    func refreshNamedTunnel() async {
        do {
            let response = try client.request(method: "named_tunnel.status", params: [:])
            if let domain = response["domain"] as? String {
                namedTunnelDomain = domain
            } else {
                namedTunnelDomain = nil
            }
        } catch {
            namedTunnelDomain = nil
        }
    }

    // MARK: - Actions

    func setEnabled(app: AppRecord, enabled: Bool) async {
        let method = enabled ? "app.start" : "app.stop"
        do {
            _ = try client.request(method: method, params: ["app_id": app.id])
            await refreshAll()
        } catch {}
    }

    func setTunnelExposed(app: AppRecord, exposed: Bool) async {
        do {
            _ = try client.request(method: "app.update", params: [
                "app_id": app.id,
                "tunnel_exposed": exposed,
            ])
            await refreshAll()
        } catch {}
    }

    func deleteApp(_ app: AppRecord) async -> Bool {
        do {
            _ = try client.request(method: "app.delete", params: ["app_id": app.id])
            await refreshAll()
            return true
        } catch {
            return false
        }
    }

    func app(byId id: String) -> AppRecord? {
        apps.first { $0.id == id }
    }
}
