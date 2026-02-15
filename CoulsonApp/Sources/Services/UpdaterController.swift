import Foundation
import Sparkle

/// Wraps Sparkle's SPUUpdater for use in SwiftUI.
/// Only active in production mode (.app bundle with SUFeedURL configured).
@MainActor
final class UpdaterController: ObservableObject {
    private let updaterController: SPUStandardUpdaterController

    @Published var canCheckForUpdates = false

    init() {
        updaterController = SPUStandardUpdaterController(
            startingUpdater: false,
            updaterDelegate: nil,
            userDriverDelegate: nil)
    }

    /// Start the updater. Call once during app launch (production mode only).
    func start() {
        guard DaemonManager.isProductionApp else { return }
        updaterController.startUpdater()
        // Observe canCheckForUpdates via KVO
        updaterController.updater.publisher(for: \.canCheckForUpdates)
            .assign(to: &$canCheckForUpdates)
    }

    func checkForUpdates() {
        updaterController.checkForUpdates(nil)
    }

    var automaticallyChecksForUpdates: Bool {
        get { updaterController.updater.automaticallyChecksForUpdates }
        set { updaterController.updater.automaticallyChecksForUpdates = newValue }
    }
}
