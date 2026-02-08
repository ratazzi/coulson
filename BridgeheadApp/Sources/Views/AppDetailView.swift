import AppKit
import SwiftUI

struct AppDetailView: View {
    @EnvironmentObject var vm: BridgeheadViewModel
    let app: AppRecord
    @Binding var path: NavigationPath
    @State private var showDeleteConfirm = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                statusBanner
                urlsSection
                infoSection
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
            Text("This will remove the app from Bridgehead. The underlying service is not affected.")
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
                ForEach(Array(app.dashboardURLs.enumerated()), id: \.offset) { index, url in
                    urlRow(url)
                    if index < app.dashboardURLs.count - 1 {
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
            Text(url)
                .font(.system(size: 13, design: .monospaced))
                .foregroundStyle(.blue)
                .lineLimit(1)
                .truncationMode(.middle)

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

            if let u = URL(string: url) {
                Button {
                    NSWorkspace.shared.open(u)
                } label: {
                    Image(systemName: "arrow.up.right.square")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .help("Open in browser")
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    // MARK: - Info

    private var infoSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader("Info")
            VStack(spacing: 0) {
                infoRow("Kind", app.kind)
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
            }
            .background(.quaternary.opacity(0.3))
            .clipShape(RoundedRectangle(cornerRadius: 8))
        }
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
