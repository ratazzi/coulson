import AppKit
import SwiftUI

struct AppRowView: View {
    @EnvironmentObject var vm: BridgeheadViewModel
    let app: AppRecord
    let onToggle: (Bool) -> Void
    @State private var isHovered = false

    var body: some View {
        HStack(spacing: 10) {
            // Status indicator
            Circle()
                .fill(app.enabled ? Color.green : Color.gray.opacity(0.35))
                .frame(width: 9, height: 9)

            // Domain + target info
            VStack(alignment: .leading, spacing: 2) {
                HStack(alignment: .firstTextBaseline, spacing: 0) {
                    Text(app.domain)
                        .font(.system(size: 13, weight: .medium))
                        .lineLimit(1)

                    if let port = app.target.port {
                        Text(":" + String(port))
                            .font(.system(size: 12, weight: .regular, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                }

                HStack(spacing: 4) {
                    Text("\u{2192}")
                        .font(.system(size: 11))
                        .foregroundStyle(.tertiary)
                    Text(app.targetLabel)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(.secondary)
                    if let prefix = app.pathPrefix {
                        Text(prefix)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.tertiary)
                    }
                }
            }

            Spacer(minLength: 4)

            // Open in browser
            Button {
                if let url = URL(string: app.primaryURL(proxyPort: vm.proxyPort)) {
                    NSWorkspace.shared.open(url)
                }
            } label: {
                Image(systemName: "safari")
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
            .focusable(false)
            .help("Open \(app.domain) in browser")

            // Toggle
            Toggle("", isOn: Binding(
                get: { app.enabled },
                set: { onToggle($0) }
            ))
            .labelsHidden()
            .toggleStyle(.switch)
            .controlSize(.small)
            .focusable(false)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(isHovered ? Color.primary.opacity(0.04) : Color(nsColor: .controlBackgroundColor))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(Color.primary.opacity(0.08), lineWidth: 1)
        )
        .shadow(color: .black.opacity(0.04), radius: 2, y: 1)
        .onHover { isHovered = $0 }
        .animation(.easeInOut(duration: 0.15), value: isHovered)
    }
}
