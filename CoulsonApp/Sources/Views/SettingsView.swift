import AppKit
import ServiceManagement
import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var vm: CoulsonViewModel
    @State private var tokenInput = ""
    @State private var domainInput = ""
    @State private var isConnecting = false
    @State private var launchAtLogin = SMAppService.mainApp.status == .enabled

    var body: some View {
        Form {
            // MARK: - General

            Section {
                Toggle("Launch at Login", isOn: $launchAtLogin)
                    .disabled(!DaemonManager.isProductionApp)
                    .onChange(of: launchAtLogin) { newValue in
                        do {
                            if newValue {
                                try SMAppService.mainApp.register()
                            } else {
                                try SMAppService.mainApp.unregister()
                            }
                        } catch {
                            vm.errorMessage = "Failed to update login item: \(error.localizedDescription)"
                            launchAtLogin = !newValue
                        }
                    }

                if let version = vm.daemonManager.daemonVersion {
                    LabeledContent("Daemon Version", value: version)
                }
            } header: {
                Text("General")
            } footer: {
                if !DaemonManager.isProductionApp {
                    Text("Launch at Login requires the Coulson.app bundle.")
                }
            }

            // MARK: - Tunnel

            Section {
                if vm.globalTunnelConnected {
                    connectedRows
                } else if vm.globalTunnelConfigured {
                    disconnectedConfiguredRows
                } else {
                    setupRows
                }
            } header: {
                Text("Cloudflare Tunnel")
            } footer: {
                Text("Expose all local apps to the internet via Cloudflare Tunnel. Each app gets a public URL like appname.\(exampleDomain).")
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Settings")
        .alert("Error", isPresented: Binding(
            get: { vm.errorMessage != nil },
            set: { if !$0 { vm.errorMessage = nil } }
        )) {
            Button("OK") { vm.errorMessage = nil }
        } message: {
            Text(vm.errorMessage ?? "")
        }
    }

    private var exampleDomain: String {
        vm.namedTunnelDomain ?? "example.com"
    }

    // MARK: - Tunnel: Connected

    @ViewBuilder
    private var connectedRows: some View {
        LabeledContent("Status") {
            HStack(spacing: 6) {
                Circle().fill(.green).frame(width: 8, height: 8)
                Text("Connected").foregroundStyle(.green)
            }
        }

        if let domain = vm.namedTunnelDomain {
            LabeledContent("Domain") {
                Text(domain).font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
            }
        }

        if let cname = vm.globalTunnelCnameTarget {
            LabeledContent("CNAME Target") {
                HStack(spacing: 6) {
                    Text(cname).font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Button {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(cname, forType: .string)
                    } label: {
                        Image(systemName: "doc.on.doc")
                            .font(.system(size: 11))
                    }
                    .buttonStyle(.borderless)
                    .help("Copy CNAME target")
                }
            }
        }

        Button(role: .destructive) {
            Task {
                isConnecting = true
                await vm.disconnectGlobalTunnel()
                isConnecting = false
            }
        } label: {
            Text("Disconnect")
        }
        .disabled(isConnecting)
    }

    // MARK: - Tunnel: Disconnected (configured)

    @ViewBuilder
    private var disconnectedConfiguredRows: some View {
        LabeledContent("Status") {
            HStack(spacing: 6) {
                Circle().fill(.orange).frame(width: 8, height: 8)
                Text("Disconnected").foregroundStyle(.secondary)
            }
        }

        if let domain = vm.namedTunnelDomain {
            LabeledContent("Domain") {
                Text(domain).font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
            }
        }

        Button {
            Task {
                isConnecting = true
                await vm.reconnectGlobalTunnel()
                isConnecting = false
            }
        } label: {
            Text("Reconnect")
        }
        .disabled(isConnecting)
    }

    // MARK: - Tunnel: Setup

    @ViewBuilder
    private var setupRows: some View {
        SecureField("Tunnel Token", text: $tokenInput)
            .font(.system(.body, design: .monospaced))
        TextField("Domain", text: $domainInput, prompt: Text("example.com"))

        Button {
            Task {
                isConnecting = true
                await vm.connectGlobalTunnel(token: tokenInput, domain: domainInput)
                if vm.globalTunnelConnected {
                    tokenInput = ""
                    domainInput = ""
                }
                isConnecting = false
            }
        } label: {
            HStack {
                if isConnecting {
                    ProgressView().controlSize(.small)
                }
                Text("Connect")
            }
        }
        .disabled(tokenInput.isEmpty || domainInput.isEmpty || isConnecting)
    }
}
