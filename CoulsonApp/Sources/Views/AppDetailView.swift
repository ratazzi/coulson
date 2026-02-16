import AppKit
import SwiftUI

struct AppDetailView: View {
    @EnvironmentObject var vm: CoulsonViewModel
    let app: AppRecord
    @Binding var path: NavigationPath
    @State private var showDeleteConfirm = false
    @State private var customTunnelTokenInput = ""
    @State private var customTunnelDomainInput = ""
    @State private var showCustomForm = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                statusBanner
                urlsSection
                infoSection
                settingsSection
                tunnelSection
                warningsSection
                dangerSection
            }
            .padding(16)
        }
        .navigationTitle(app.domain)
        .confirmationDialog(
            "Delete \(app.domain)?",
            isPresented: $showDeleteConfirm,
            titleVisibility: .visible
        ) {
            Button("Delete", role: .destructive) {
                Task {
                    let ok = await vm.deleteApp(app)
                    if ok, !path.isEmpty {
                        path.removeLast()
                    }
                }
            }
        } message: {
            Text("This will remove the app from Coulson. The underlying service is not affected.")
        }
        .alert("Error", isPresented: Binding(
            get: { vm.errorMessage != nil },
            set: { if !$0 { vm.errorMessage = nil } }
        )) {
            Button("OK") { vm.errorMessage = nil }
        } message: {
            Text(vm.errorMessage ?? "")
        }
        .onChange(of: app.tunnelMode) { newMode in
            if newMode != "named" {
                showCustomForm = false
            }
        }
    }

    // MARK: - Status Banner

    private var statusBanner: some View {
        HStack {
            Label(
                app.enabled ? "Running" : "Stopped",
                systemImage: app.enabled ? "circle.fill" : "circle"
            )
            .font(.system(size: 13, weight: .medium))
            .foregroundStyle(app.enabled ? .green : .secondary)

            Spacer()

            Toggle("", isOn: Binding(
                get: { app.enabled },
                set: { enabled in
                    Task { await vm.setEnabled(app: app, enabled: enabled) }
                }
            ))
            .labelsHidden()
            .toggleStyle(.switch)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(.quaternary.opacity(0.5))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    // MARK: - URLs

    private var urlsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader("URLs")
            VStack(spacing: 0) {
                ForEach(Array(app.dashboardURLs(proxyPort: vm.proxyPort, httpsPort: vm.httpsPort).enumerated()), id: \.offset) { index, url in
                    urlRow(url)
                    if index < app.dashboardURLs(proxyPort: vm.proxyPort, httpsPort: vm.httpsPort).count - 1 {
                        Divider().padding(.leading, 12)
                    }
                }
            }
            .background(.quaternary.opacity(0.3))
            .clipShape(RoundedRectangle(cornerRadius: 8))
        }
    }

    private func urlRow(_ url: String) -> some View {
        HStack {
            if let u = URL(string: url) {
                Button {
                    NSWorkspace.shared.open(u)
                } label: {
                    Text(url)
                        .font(.system(size: 13, design: .monospaced))
                        .foregroundStyle(.blue)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                .buttonStyle(.plain)
                .onHover { inside in
                    if inside { NSCursor.pointingHand.push() } else { NSCursor.pop() }
                }
            } else {
                Text(url)
                    .font(.system(size: 13, design: .monospaced))
                    .foregroundStyle(.blue)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            Spacer(minLength: 8)

            Button {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(url, forType: .string)
            } label: {
                Image(systemName: "doc.on.doc")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
            .help("Copy URL")
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    // MARK: - Info

    private var infoSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader("Info")
            VStack(spacing: 0) {
                infoRow("Kind", app.kindLabel)
                Divider().padding(.leading, 12)
                infoRow("Port", app.target.port.map { "\($0)" } ?? "—")
                Divider().padding(.leading, 12)
                infoRow("Target", app.targetLabel)
                if let prefix = app.pathPrefix {
                    Divider().padding(.leading, 12)
                    infoRow("Path prefix", prefix)
                }
                Divider().padding(.leading, 12)
                infoRow("Timeout", app.timeoutMs.map { "\($0) ms" } ?? "default")
                if let root = app.target.root {
                    Divider().padding(.leading, 12)
                    pathRow("Root", root)
                }
                if app.target.type == "managed" {
                    Divider().padding(.leading, 12)
                    pathRow("Log", (vm.runtimeDir as NSString).appendingPathComponent("managed/\(app.name).log"))
                }
            }
            .background(.quaternary.opacity(0.3))
            .clipShape(RoundedRectangle(cornerRadius: 8))
        }
    }

    // MARK: - Settings

    private var settingsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader("Settings")
            VStack(spacing: 0) {
                settingsToggleRow("CORS", value: app.corsEnabled) { val in
                    Task { await vm.updateApp(app: app, params: ["cors_enabled": val]) }
                }
                Divider().padding(.leading, 12)
                settingsToggleRow("SPA Rewrite", value: app.spaRewrite) { val in
                    Task { await vm.updateApp(app: app, params: ["spa_rewrite": val]) }
                }
                Divider().padding(.leading, 12)
                basicAuthRow
                if let port = app.listenPort {
                    Divider().padding(.leading, 12)
                    infoRow("Listen port", "\(port)")
                }
            }
            .background(.quaternary.opacity(0.3))
            .clipShape(RoundedRectangle(cornerRadius: 8))
        }
    }

    private func settingsToggleRow(_ label: String, value: Bool, onChange: @escaping (Bool) -> Void) -> some View {
        HStack {
            Text(label)
                .font(.system(size: 13))
            Spacer()
            Toggle("", isOn: Binding(
                get: { value },
                set: { onChange($0) }
            ))
            .labelsHidden()
            .toggleStyle(.switch)
            .controlSize(.small)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    private var basicAuthRow: some View {
        HStack {
            Text("Basic Auth")
                .font(.system(size: 13))
                .foregroundStyle(.secondary)
                .frame(width: 90, alignment: .leading)
            if let user = app.basicAuthUser, !user.isEmpty {
                Text(user)
                    .font(.system(size: 13, design: .monospaced))
                    .lineLimit(1)
            } else {
                Text("off")
                    .font(.system(size: 13))
                    .foregroundStyle(.tertiary)
            }
            Spacer()
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
    }

    // MARK: - Tunnel

    // Picker visual state: stays on "named" while custom form is open
    private var pickerSelection: String {
        if showCustomForm { return "named" }
        return app.tunnelMode
    }

    private var tunnelSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader("Tunnel")
            VStack(spacing: 0) {
                tunnelURLDisplay
                tunnelModePicker

                // Global mode hint when tunnel not connected
                if app.tunnelMode == "global" && !vm.globalTunnelConnected {
                    Divider().padding(.leading, 12)
                    HStack {
                        Text("Global tunnel not connected. Set up in Settings.")
                            .font(.system(size: 12))
                            .foregroundStyle(.secondary)
                        Spacer()
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                }

                // Custom tunnel form
                if showCustomForm {
                    Divider().padding(.leading, 12)
                    customTunnelForm
                }

                // Existing custom domain info
                if !showCustomForm && app.tunnelMode == "named", let domain = app.appTunnelDomain {
                    Divider().padding(.leading, 12)
                    infoRow("Domain", domain)
                }
            }
            .background(.quaternary.opacity(0.3))
            .clipShape(RoundedRectangle(cornerRadius: 8))
        }
    }

    @ViewBuilder
    private var tunnelURLDisplay: some View {
        if !showCustomForm {
            if app.tunnelMode == "global", vm.globalTunnelConnected,
               let url = vm.globalTunnelURL(for: app) {
                urlRow(url)
                Divider().padding(.leading, 12)
            } else if app.tunnelMode == "quick", let url = app.tunnelUrl {
                urlRow(url)
                Divider().padding(.leading, 12)
            } else if app.tunnelMode == "named", let domain = app.appTunnelDomain {
                urlRow("https://\(domain)")
                Divider().padding(.leading, 12)
            }
        }
    }

    private var tunnelModePicker: some View {
        HStack {
            Text("Mode")
                .font(.system(size: 13))
            Spacer()
            Picker("", selection: Binding(
                get: { pickerSelection },
                set: { mode in
                    if mode == "named" {
                        showCustomForm = true
                        customTunnelTokenInput = ""
                        customTunnelDomainInput = ""
                    } else {
                        showCustomForm = false
                        Task { await vm.updateApp(app: app, params: ["tunnel_mode": mode]) }
                    }
                }
            )) {
                Text("Off").tag("none")
                Text("Global").tag("global")
                Text("Quick").tag("quick")
                Text("Custom").tag("named")
            }
            .labelsHidden()
            .pickerStyle(.segmented)
            .frame(width: 280)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    private var customTunnelForm: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Token")
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(.secondary)
            SecureField("eyJh...  (from CF tunnel install command)", text: $customTunnelTokenInput)
                .textFieldStyle(.roundedBorder)
                .font(.system(size: 12, design: .monospaced))

            Text("Domain")
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(.secondary)
            TextField("myapp.example.com", text: $customTunnelDomainInput)
                .textFieldStyle(.roundedBorder)
                .font(.system(size: 12))

            HStack {
                Button("Cancel") {
                    showCustomForm = false
                }
                .controlSize(.small)
                Button("Connect") {
                    let token = customTunnelTokenInput.trimmingCharacters(in: .whitespaces)
                    let domain = customTunnelDomainInput.trimmingCharacters(in: .whitespaces)
                    guard !token.isEmpty, !domain.isEmpty else { return }
                    Task {
                        await vm.updateApp(app: app, params: [
                            "tunnel_mode": "named",
                            "app_tunnel_domain": domain,
                            "app_tunnel_token": token,
                        ])
                        showCustomForm = false
                    }
                }
                .controlSize(.small)
                .disabled(customTunnelTokenInput.isEmpty || customTunnelDomainInput.isEmpty)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    // MARK: - Warnings

    private var warningsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader("Scan Warnings")
            VStack(alignment: .leading, spacing: 6) {
                if vm.warningLines.isEmpty {
                    HStack {
                        Image(systemName: "checkmark.circle")
                            .foregroundStyle(.green)
                        Text("No issues detected")
                            .font(.system(size: 13))
                            .foregroundStyle(.secondary)
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                } else {
                    ForEach(vm.warningLines, id: \.self) { line in
                        HStack(alignment: .top) {
                            Image(systemName: "exclamationmark.triangle")
                                .foregroundStyle(.orange)
                                .font(.system(size: 11))
                            Text(line)
                                .font(.system(size: 12))
                                .foregroundStyle(.secondary)
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 4)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.quaternary.opacity(0.3))
            .clipShape(RoundedRectangle(cornerRadius: 8))
        }
    }

    // MARK: - Danger Zone

    private var dangerSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader("Danger Zone")
            HStack {
                Button(role: .destructive) {
                    showDeleteConfirm = true
                } label: {
                    Label("Delete App", systemImage: "trash")
                        .font(.system(size: 13))
                }
                Spacer()
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            .background(.quaternary.opacity(0.3))
            .clipShape(RoundedRectangle(cornerRadius: 8))
        }
    }

    // MARK: - Helpers

    private func sectionHeader(_ title: String) -> some View {
        Text(title)
            .font(.system(size: 12, weight: .semibold))
            .foregroundStyle(.secondary)
            .textCase(.uppercase)
            .padding(.leading, 2)
    }

    private func pathRow(_ key: String, _ path: String) -> some View {
        HStack {
            Text(key)
                .font(.system(size: 13))
                .foregroundStyle(.secondary)
                .frame(width: 90, alignment: .leading)
            Button {
                let url = URL(fileURLWithPath: path)
                NSWorkspace.shared.activateFileViewerSelecting([url])
            } label: {
                Text(path)
                    .font(.system(size: 13, design: .monospaced))
                    .foregroundStyle(.blue)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            .buttonStyle(.plain)
            .onHover { inside in
                if inside { NSCursor.pointingHand.push() } else { NSCursor.pop() }
            }
            Spacer(minLength: 8)
            Button {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(path, forType: .string)
            } label: {
                Image(systemName: "doc.on.doc")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
            .help("Copy path")
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
    }

    private func infoRow(_ key: String, _ value: String) -> some View {
        HStack {
            Text(key)
                .font(.system(size: 13))
                .foregroundStyle(.secondary)
                .frame(width: 90, alignment: .leading)
            Text(value)
                .font(.system(size: 13, design: .monospaced))
                .lineLimit(1)
            Spacer()
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
    }
}
