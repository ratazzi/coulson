import AppKit
import SwiftUI

struct MenuPanel: View {
    @EnvironmentObject var vm: CoulsonViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                Circle()
                    .fill(vm.isHealthy ? Color.green : Color.orange)
                    .frame(width: 7, height: 7)
                Text("Coulson")
                    .font(.headline)
            }

            Text(vm.subtitle)
                .font(.caption)
                .foregroundStyle(.secondary)

            Divider()

            Button("Open Dashboard") {
                NSApplication.shared.activate(ignoringOtherApps: true)
                for window in NSApplication.shared.windows where window.title.contains("Coulson") {
                    window.makeKeyAndOrderFront(nil)
                }
            }
            .keyboardShortcut("d")

            if !vm.apps.isEmpty {
                Divider()
                ForEach(vm.sortedApps.prefix(5)) { app in
                    Button {
                        if let url = URL(string: app.primaryURL(proxyPort: vm.proxyPort)) {
                            NSWorkspace.shared.open(url)
                        }
                    } label: {
                        HStack(spacing: 6) {
                            Circle()
                                .fill(app.enabled ? Color.green : Color.gray.opacity(0.35))
                                .frame(width: 6, height: 6)
                            Text(app.domain)
                                .lineLimit(1)
                        }
                    }
                }
                if vm.apps.count > 5 {
                    Text("\(vm.apps.count - 5) more...")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
            }

            Divider()
            Button("Quit Coulson") {
                NSApplication.shared.terminate(nil)
            }
            .keyboardShortcut("q")
        }
        .padding(8)
        .task { await vm.refreshAll() }
    }
}
