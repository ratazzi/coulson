import SwiftUI

enum DashboardDestination: Hashable {
    case appDetail(String)
    case addApp
    case settings
}

struct DashboardView: View {
    @EnvironmentObject var vm: BridgeheadViewModel
    @State private var path = NavigationPath()
    @State private var searchText = ""

    var body: some View {
        NavigationStack(path: $path) {
            AppListView(path: $path, searchText: $searchText)
                .navigationDestination(for: DashboardDestination.self) { dest in
                    switch dest {
                    case .appDetail(let appId):
                        if let app = vm.app(byId: appId) {
                            AppDetailView(app: app, path: $path)
                        }
                    case .addApp:
                        AddAppView(path: $path)
                    case .settings:
                        SettingsView()
                    }
                }
        }
        .task { await vm.startAutoRefresh() }
        .onDisappear { vm.stopAutoRefresh() }
    }
}

struct AppListView: View {
    @EnvironmentObject var vm: BridgeheadViewModel
    @Binding var path: NavigationPath
    @Binding var searchText: String

    private var filteredApps: [AppRecord] {
        let sorted = vm.sortedApps
        if searchText.isEmpty { return sorted }
        let query = searchText.lowercased()
        return sorted.filter {
            $0.domain.lowercased().contains(query)
            || $0.targetLabel.lowercased().contains(query)
            || ($0.target.port.map { String($0).contains(query) } ?? false)
        }
    }

    var body: some View {
        Group {
            if vm.apps.isEmpty && vm.isHealthy {
                emptyState
            } else if !vm.isHealthy {
                offlineState
            } else {
                appList
            }
        }
        .navigationTitle("Bridgehead")
        .navigationSubtitle(vm.subtitle)
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                HStack(spacing: 8) {
                    Button {
                        path.append(DashboardDestination.addApp)
                    } label: {
                        Image(systemName: "plus")
                    }
                    Button {
                        path.append(DashboardDestination.settings)
                    } label: {
                        Image(systemName: "gearshape")
                    }
                }
            }
        }
    }

    // MARK: - App List

    private var appList: some View {
        ScrollView {
            LazyVStack(spacing: 8) {
                // Inline search bar
                HStack(spacing: 6) {
                    Image(systemName: "magnifyingglass")
                        .font(.system(size: 12))
                        .foregroundStyle(.tertiary)
                    TextField("Filter by domain or port", text: $searchText)
                        .textFieldStyle(.plain)
                        .font(.system(size: 13))
                    if !searchText.isEmpty {
                        Button {
                            searchText = ""
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                                .font(.system(size: 12))
                                .foregroundStyle(.tertiary)
                        }
                        .buttonStyle(.plain)
                        .focusable(false)
                    }
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 6)
                .background(
                    RoundedRectangle(cornerRadius: 8)
                        .fill(Color.primary.opacity(0.04))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(Color.primary.opacity(0.06), lineWidth: 1)
                )

                ForEach(filteredApps) { app in
                    AppRowView(app: app) { enabled in
                        Task { await vm.setEnabled(app: app, enabled: enabled) }
                    }
                    .contentShape(Rectangle())
                    .onTapGesture { path.append(DashboardDestination.appDetail(app.id)) }
                }
            }
            .padding(.horizontal, 12)
            .padding(.top, 8)
            .padding(.bottom, 12)
        }
    }

    // MARK: - Empty / Offline States

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "server.rack")
                .font(.system(size: 36))
                .foregroundStyle(.tertiary)
            Text("No Apps")
                .font(.headline)
                .foregroundStyle(.secondary)
            Text("Add powfiles or bridgehead.json\nto your apps directory.")
                .font(.caption)
                .foregroundStyle(.tertiary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var offlineState: some View {
        VStack(spacing: 12) {
            Image(systemName: "bolt.horizontal.circle")
                .font(.system(size: 36))
                .foregroundStyle(.orange)
            Text("Daemon Offline")
                .font(.headline)
                .foregroundStyle(.secondary)
            Text("bridgeheadd is not running.\nStart it with `mise run daemon`.")
                .font(.caption)
                .foregroundStyle(.tertiary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

}
