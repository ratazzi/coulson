import AppKit
import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var vm: CoulsonViewModel
    @State private var tokenInput = ""
    @State private var domainInput = ""
    @State private var isConnecting = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                tunnelSection
            }
            .padding(16)
        }
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

    // MARK: - Tunnel Section

    @ViewBuilder
    private var tunnelSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Cloudflare Wildcard Tunnel", systemImage: "globe")
                .font(.headline)

            Text("Expose all local apps to the internet via Cloudflare Tunnel. Each app gets a public URL like appname.\(exampleDomain).")
                .font(.system(size: 13))
                .foregroundStyle(.secondary)

            if vm.globalTunnelConnected {
                connectedView
            } else if vm.globalTunnelConfigured {
                disconnectedConfiguredView
            } else {
                setupForm
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(Color.primary.opacity(0.03))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(Color.primary.opacity(0.06), lineWidth: 1)
        )
    }

    private var exampleDomain: String {
        vm.namedTunnelDomain ?? "example.com"
    }

    // MARK: - Connected

    private var connectedView: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 6) {
                Circle()
                    .fill(.green)
                    .frame(width: 8, height: 8)
                Text("Connected")
                    .font(.subheadline.weight(.medium))
                    .foregroundStyle(.green)
            }

            if let domain = vm.namedTunnelDomain {
                infoRow("Domain", domain)
            }
            if let cname = vm.globalTunnelCnameTarget {
                cnameRow(cname)
            }

            Button(role: .destructive) {
                Task {
                    isConnecting = true
                    await vm.disconnectGlobalTunnel()
                    isConnecting = false
                }
            } label: {
                Text("Disconnect")
                    .frame(maxWidth: .infinity)
            }
            .disabled(isConnecting)
        }
    }

    // MARK: - Disconnected (configured)

    private var disconnectedConfiguredView: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 6) {
                Circle()
                    .fill(.orange)
                    .frame(width: 8, height: 8)
                Text("Disconnected")
                    .font(.subheadline.weight(.medium))
                    .foregroundStyle(.secondary)
            }

            if let domain = vm.namedTunnelDomain {
                infoRow("Domain", domain)
            }

            Button {
                Task {
                    isConnecting = true
                    await vm.reconnectGlobalTunnel()
                    isConnecting = false
                }
            } label: {
                Text("Reconnect")
                    .frame(maxWidth: .infinity)
            }
            .disabled(isConnecting)
        }
    }

    // MARK: - Setup Form

    private var setupForm: some View {
        VStack(alignment: .leading, spacing: 12) {
            // Step-by-step guide
            VStack(alignment: .leading, spacing: 8) {
                stepRow(1, "Go to Cloudflare Zero Trust \u{2192} Networks \u{2192} Tunnels, create a tunnel")
                stepRow(2, "Copy the tunnel token (the long string after `--token`)")
                stepRow(3, "Fill in the token and your domain below, then Connect")
                stepRow(4, "Add a wildcard DNS record (shown after connecting)")
            }

            Divider()

            VStack(alignment: .leading, spacing: 8) {
                Text("Token")
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(.secondary)
                SecureField("eyJh...  (from tunnel install command)", text: $tokenInput)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 13, design: .monospaced))

                Text("Domain")
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(.secondary)
                TextField("example.com", text: $domainInput)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 13))
            }

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
                        ProgressView()
                            .controlSize(.small)
                    }
                    Text("Connect")
                }
                .frame(maxWidth: .infinity)
            }
            .disabled(tokenInput.isEmpty || domainInput.isEmpty || isConnecting)
        }
    }

    // MARK: - Helpers

    private func stepRow(_ number: Int, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text("\(number)")
                .font(.system(size: 11, weight: .bold, design: .rounded))
                .foregroundStyle(.white)
                .frame(width: 18, height: 18)
                .background(Circle().fill(.secondary))
            Text(text)
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
        }
    }

    private func infoRow(_ label: String, _ value: String) -> some View {
        HStack {
            Text(label)
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
                .frame(width: 60, alignment: .leading)
            Text(value)
                .font(.system(size: 12, design: .monospaced))
                .textSelection(.enabled)
            Spacer()
        }
        .padding(.vertical, 2)
    }

    private func cnameRow(_ cname: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text("DNS")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                    .frame(width: 60, alignment: .leading)
                Text("*.\(vm.namedTunnelDomain ?? "domain") \u{2192} \(cname)")
                    .font(.system(size: 12, design: .monospaced))
                    .textSelection(.enabled)
                Spacer(minLength: 4)
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(cname, forType: .string)
                } label: {
                    Image(systemName: "doc.on.doc")
                        .font(.system(size: 10))
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .help("Copy CNAME target")
            }
            Text("Add this CNAME record in your DNS provider if not already set.")
                .font(.system(size: 11))
                .foregroundStyle(.tertiary)
        }
        .padding(.vertical, 2)
    }
}
