import SwiftUI

enum AppType: String, CaseIterable {
    case tcp = "TCP Proxy"
    case staticDir = "Static Dir"
    case unixSocket = "Unix Socket"
}

struct AddAppView: View {
    @EnvironmentObject var vm: CoulsonViewModel
    @Binding var path: NavigationPath

    @State private var appType: AppType = .tcp
    @State private var name = ""
    @State private var host = "127.0.0.1"
    @State private var port = ""
    @State private var staticRoot = ""
    @State private var socketPath = ""
    @State private var isCreating = false

    private var domainPrefix: String {
        name.trimmingCharacters(in: .whitespaces).lowercased()
    }

    private var canCreate: Bool {
        if domainPrefix.isEmpty { return false }
        switch appType {
        case .tcp:
            return !port.isEmpty && UInt16(port) != nil && UInt16(port)! > 0
        case .staticDir:
            return !staticRoot.trimmingCharacters(in: .whitespaces).isEmpty
        case .unixSocket:
            return !socketPath.trimmingCharacters(in: .whitespaces).isEmpty
        }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Type picker
                VStack(alignment: .leading, spacing: 8) {
                    sectionHeader("Type")
                    Picker("", selection: $appType) {
                        ForEach(AppType.allCases, id: \.self) { type in
                            Text(type.rawValue).tag(type)
                        }
                    }
                    .labelsHidden()
                    .pickerStyle(.segmented)
                }

                // Common fields
                VStack(alignment: .leading, spacing: 8) {
                    sectionHeader("General")
                    VStack(spacing: 0) {
                        fieldRow("Name") {
                            TextField("My App", text: $name)
                                .textFieldStyle(.plain)
                                .font(.system(size: 13))
                        }
                        Divider().padding(.leading, 12)
                        fieldRow("Domain") {
                            HStack(spacing: 2) {
                                Text(domainPrefix.isEmpty ? "—" : domainPrefix)
                                    .font(.system(size: 13))
                                    .foregroundStyle(domainPrefix.isEmpty ? .tertiary : .primary)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                Text(".\(vm.domainSuffix)")
                                    .font(.system(size: 11))
                                    .foregroundStyle(.tertiary)
                                    .fixedSize()
                            }
                        }
                    }
                    .background(.quaternary.opacity(0.3))
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                }

                // Type-specific fields
                switch appType {
                case .tcp:
                    tcpFields
                case .staticDir:
                    staticDirFields
                case .unixSocket:
                    unixSocketFields
                }

                // Create
                HStack {
                    Button {
                        Task { await create() }
                    } label: {
                        Label("Create App", systemImage: "plus.circle")
                            .font(.system(size: 13))
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.regular)
                    .disabled(!canCreate || isCreating)
                }
            }
            .padding(16)
        }
        .navigationTitle("Add App")
        .alert("Error", isPresented: Binding(
            get: { vm.errorMessage != nil },
            set: { if !$0 { vm.errorMessage = nil } }
        )) {
            Button("OK") { vm.errorMessage = nil }
        } message: {
            Text(vm.errorMessage ?? "")
        }
    }

    // MARK: - Type-specific fields

    private var tcpFields: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader("Target")
            VStack(spacing: 0) {
                fieldRow("Host") {
                    TextField("127.0.0.1", text: $host)
                        .textFieldStyle(.plain)
                        .font(.system(size: 13))
                }
                Divider().padding(.leading, 12)
                fieldRow("Port") {
                    TextField("3000", text: $port)
                        .textFieldStyle(.plain)
                        .font(.system(size: 13))
                }
            }
            .background(.quaternary.opacity(0.3))
            .clipShape(RoundedRectangle(cornerRadius: 8))
        }
    }

    private var staticDirFields: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader("Target")
            VStack(spacing: 0) {
                HStack {
                    Text("Root")
                        .font(.system(size: 13))
                        .foregroundStyle(.secondary)
                        .frame(width: 60, alignment: .leading)
                    TextField("/path/to/directory", text: $staticRoot)
                        .textFieldStyle(.plain)
                        .font(.system(size: 13))
                    Button("Browse…") {
                        let panel = NSOpenPanel()
                        panel.canChooseDirectories = true
                        panel.canChooseFiles = false
                        panel.allowsMultipleSelection = false
                        if panel.runModal() == .OK, let url = panel.url {
                            staticRoot = url.path
                        }
                    }
                    .controlSize(.small)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
            }
            .background(.quaternary.opacity(0.3))
            .clipShape(RoundedRectangle(cornerRadius: 8))
        }
    }

    private var unixSocketFields: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader("Target")
            VStack(spacing: 0) {
                fieldRow("Socket") {
                    TextField("/tmp/myapp.sock", text: $socketPath)
                        .textFieldStyle(.plain)
                        .font(.system(size: 13))
                }
            }
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

    private func fieldRow<Content: View>(_ label: String, @ViewBuilder content: () -> Content) -> some View {
        HStack {
            Text(label)
                .font(.system(size: 13))
                .foregroundStyle(.secondary)
                .frame(width: 60, alignment: .leading)
            content()
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    // MARK: - Create

    private func create() async {
        isCreating = true
        defer { isCreating = false }

        var params: [String: Any] = [
            "name": name.trimmingCharacters(in: .whitespaces),
            "domain": "\(domainPrefix).\(vm.domainSuffix)",
        ]

        switch appType {
        case .tcp:
            let h = host.trimmingCharacters(in: .whitespaces)
            params["target_type"] = "tcp"
            params["target_value"] = "\(h):\(port)"
        case .staticDir:
            params["target_type"] = "static_dir"
            params["target_value"] = staticRoot.trimmingCharacters(in: .whitespaces)
        case .unixSocket:
            params["target_type"] = "unix_socket"
            params["target_value"] = socketPath.trimmingCharacters(in: .whitespaces)
        }

        let appId = await vm.createApp(params: params)
        if appId != nil, !path.isEmpty {
            path.removeLast()
        }
    }
}
