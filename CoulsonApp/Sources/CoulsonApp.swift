import AppKit
import Sparkle
import SwiftUI

extension Notification.Name {
    static let openSettings = Notification.Name("com.coulson.openSettings")
}

@main
struct CoulsonAppMain: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @StateObject private var vm = CoulsonViewModel()
    @StateObject private var updater = UpdaterController()

    var body: some Scene {
        WindowGroup("Coulson") {
            DashboardView()
                .environmentObject(vm)
                .frame(minWidth: 360, minHeight: 320)
                .task {
                    appDelegate.setupStatusBar(vm: vm, updater: updater)
                    if DaemonManager.isProductionApp {
                        updater.start()
                        await vm.daemonManager.ensureRunning()
                    }
                }
        }
        .defaultSize(width: 420, height: 520)
        .windowResizability(.contentMinSize)
    }
}

class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem?
    private(set) var vm: CoulsonViewModel?
    private(set) var updater: UpdaterController?
    private var refreshTask: Task<Void, Never>?

    func applicationWillFinishLaunching(_ notification: Notification) {
        if !DaemonManager.isProductionApp {
            NSApplication.shared.setActivationPolicy(.regular)
        }
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        if let iconURL = Bundle.appResources.url(forResource: "AppIcon", withExtension: "png"),
           let icon = NSImage(contentsOf: iconURL)
        {
            NSApplication.shared.applicationIconImage = icon
        }
        if !DaemonManager.isProductionApp {
            NSApplication.shared.activate(ignoringOtherApps: true)
        }
    }

    func application(_ application: NSApplication, open urls: [URL]) {
        guard let vm else { return }
        for url in urls {
            var isDir: ObjCBool = false
            guard url.isFileURL,
                  FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir),
                  isDir.boolValue else { continue }

            Task { @MainActor in
                let result = await vm.createAppFromDrop(folderPath: url.path)
                switch result {
                case .created:
                    break
                case .detectionFailed:
                    NSApplication.shared.activate(ignoringOtherApps: true)
                    for window in NSApplication.shared.windows where window.title.contains("Coulson") {
                        window.makeKeyAndOrderFront(nil)
                    }
                case .error:
                    break
                }
            }
        }
    }

    @MainActor
    func setupStatusBar(vm: CoulsonViewModel, updater: UpdaterController) {
        guard statusItem == nil else { return }
        self.vm = vm
        self.updater = updater

        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let image = Self.loadMenuBarIcon() {
            image.isTemplate = true
            statusItem?.button?.image = image
        } else {
            statusItem?.button?.image = NSImage(
                systemSymbolName: "point.3.connected.trianglepath.dotted",
                accessibilityDescription: "Coulson")
        }

        let menu = NSMenu()
        menu.delegate = self
        statusItem?.menu = menu

        // Add drop target overlay on status bar button
        if let button = statusItem?.button {
            let dropView = StatusBarDropView(frame: button.bounds, vm: vm)
            dropView.autoresizingMask = [.width, .height]
            button.addSubview(dropView)
        }

        refreshTask = Task {
            await vm.refreshAll()
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 1_500_000_000)
                await vm.refreshAll()
            }
        }
    }
}

// MARK: - Menu Bar Icon

extension AppDelegate {
    /// Loads the menu bar icon from bundle resources.
    /// Xcode/Tuist builds produce a merged tiff; SPM `swift run` keeps separate PNGs.
    static func loadMenuBarIcon() -> NSImage? {
        let bundle = Bundle.appResources
        let size = NSSize(width: 18, height: 18)

        // Xcode build: COMBINE_HIDPI_IMAGES merges 1x+2x into a single tiff
        if let url = bundle.url(forResource: "MenuBarIcon", withExtension: "tiff"),
           let image = NSImage(contentsOf: url)
        {
            image.size = size
            return image
        }

        // SPM build: separate PNG files
        if let url1x = bundle.url(forResource: "MenuBarIcon", withExtension: "png"),
           let url2x = bundle.url(forResource: "MenuBarIcon@2x", withExtension: "png"),
           let rep1x = NSImageRep(contentsOf: url1x),
           let rep2x = NSImageRep(contentsOf: url2x)
        {
            let image = NSImage(size: size)
            rep1x.size = size
            rep2x.size = size
            image.addRepresentation(rep1x)
            image.addRepresentation(rep2x)
            return image
        }

        return nil
    }
}

// MARK: - StatusBarDropView

class StatusBarDropView: NSView {
    private weak var vm: CoulsonViewModel?

    init(frame: NSRect, vm: CoulsonViewModel) {
        self.vm = vm
        super.init(frame: frame)
        registerForDraggedTypes([.fileURL])
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func draggingEntered(_ sender: any NSDraggingInfo) -> NSDragOperation {
        guard let urls = sender.draggingPasteboard.readObjects(
            forClasses: [NSURL.self],
            options: [.urlReadingFileURLsOnly: true]
        ) as? [URL] else {
            return []
        }
        for url in urls {
            var isDir: ObjCBool = false
            if FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir), isDir.boolValue {
                return .copy
            }
        }
        return []
    }

    override func performDragOperation(_ sender: any NSDraggingInfo) -> Bool {
        guard let urls = sender.draggingPasteboard.readObjects(
            forClasses: [NSURL.self],
            options: [.urlReadingFileURLsOnly: true]
        ) as? [URL] else {
            return false
        }

        for url in urls {
            var isDir: ObjCBool = false
            guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir),
                  isDir.boolValue else { continue }

            Task { @MainActor [weak self] in
                guard let vm = self?.vm else { return }
                let result = await vm.createAppFromDrop(folderPath: url.path)
                switch result {
                case .created:
                    break // app list refreshes automatically
                case .detectionFailed:
                    // Open main window and navigate to AddAppView
                    NSApplication.shared.activate(ignoringOtherApps: true)
                    for window in NSApplication.shared.windows where window.title.contains("Coulson") {
                        window.makeKeyAndOrderFront(nil)
                    }
                case .error:
                    break // errorMessage already set by vm
                }
            }
        }
        return true
    }

    override func mouseDown(with event: NSEvent) {
        // Forward click to the status bar button so menu still works
        superview?.mouseDown(with: event)
    }
}

// MARK: - NSMenuDelegate

extension AppDelegate: NSMenuDelegate {
    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        guard let vm else { return }
        MenuBuilder.build(menu: menu, vm: vm, updater: updater, target: self)
    }
}

// MARK: - Menu Actions

extension AppDelegate {
    @objc func openDashboard() {
        NSApplication.shared.activate(ignoringOtherApps: true)
        for window in NSApplication.shared.windows where window.title.contains("Coulson") {
            window.makeKeyAndOrderFront(nil)
        }
    }

    @objc func openWebDashboard() {
        Task { @MainActor in
            guard let vm = self.vm, let port = vm.proxyPort else { return }
            let urlStr = "http://\(vm.domainSuffix):\(port)/"
            if let url = URL(string: urlStr) {
                NSWorkspace.shared.open(url)
            }
        }
    }

    @objc func toggleApp(_ sender: NSMenuItem) {
        guard let box = sender.representedObject as? AppRecordBox else { return }
        let app = box.app
        Task { @MainActor in await vm?.setEnabled(app: app, enabled: !app.enabled) }
    }

    @objc func openInBrowser(_ sender: NSMenuItem) {
        guard let box = sender.representedObject as? AppRecordBox else { return }
        let app = box.app
        Task { @MainActor in
            guard let vm = self.vm else { return }
            if let url = URL(string: app.primaryURL(proxyPort: vm.proxyPort)) {
                NSWorkspace.shared.open(url)
            }
        }
    }

    @objc func copyURL(_ sender: NSMenuItem) {
        guard let box = sender.representedObject as? AppRecordBox else { return }
        let app = box.app
        Task { @MainActor in
            guard let vm = self.vm else { return }
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(
                app.primaryURL(proxyPort: vm.proxyPort), forType: .string)
        }
    }

    @objc func copyHTTPSURL(_ sender: NSMenuItem) {
        guard let box = sender.representedObject as? AppRecordBox else { return }
        let app = box.app
        Task { @MainActor in
            guard let vm = self.vm else { return }
            if let url = app.httpsURL(httpsPort: vm.httpsPort) {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(url, forType: .string)
            }
        }
    }

    @objc func openLogs(_ sender: NSMenuItem) {
        guard let box = sender.representedObject as? AppRecordBox else { return }
        Task { @MainActor in
            guard let vm = self.vm else { return }
            let dir = (vm.runtimeDir as NSString).appendingPathComponent("managed")
            let logPath = (dir as NSString).appendingPathComponent("\(box.app.name).log")
            if FileManager.default.fileExists(atPath: logPath) {
                NSWorkspace.shared.selectFile(logPath, inFileViewerRootedAtPath: dir)
            } else if FileManager.default.fileExists(atPath: dir) {
                NSWorkspace.shared.open(URL(fileURLWithPath: dir))
            }
        }
    }

    @objc func toggleTunnel(_ sender: NSMenuItem) {
        guard let box = sender.representedObject as? AppRecordBox else { return }
        let app = box.app
        Task { @MainActor in
            await vm?.updateApp(app: app, params: ["tunnel_exposed": !app.tunnelExposed])
        }
    }

    @objc func copyTunnelURL(_ sender: NSMenuItem) {
        guard let box = sender.representedObject as? AppRecordBox, let vm else { return }
        Task { @MainActor in
            if let url = vm.tunnelURL(for: box.app) {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(url, forType: .string)
            }
        }
    }

    @objc func deleteApp(_ sender: NSMenuItem) {
        guard let box = sender.representedObject as? AppRecordBox else { return }
        let app = box.app
        Task { @MainActor in _ = await vm?.deleteApp(app) }
    }

    @objc func startDaemon() {
        guard let vm else { return }
        Task { @MainActor in
            do {
                try vm.daemonManager.install()
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                await vm.refreshHealth()
            } catch {
                vm.errorMessage = error.localizedDescription
            }
        }
    }

    @objc func stopDaemon() {
        guard let vm else { return }
        Task { @MainActor in
            do {
                try vm.daemonManager.stop()
                try? await Task.sleep(nanoseconds: 500_000_000)
                await vm.refreshHealth()
            } catch {
                vm.errorMessage = error.localizedDescription
            }
        }
    }

    @objc func restartDaemon() {
        guard let vm else { return }
        Task { @MainActor in
            do {
                try vm.daemonManager.restart()
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                await vm.refreshHealth()
            } catch {
                vm.errorMessage = error.localizedDescription
            }
        }
    }

    @objc func installCLI() {
        guard let vm else { return }
        Task { @MainActor in
            do {
                try vm.daemonManager.installCLI()
                vm.objectWillChange.send()
                let alert = NSAlert()
                alert.messageText = "CLI Installed"
                alert.informativeText = "You can now use the \"coulson\" command in your terminal."
                alert.alertStyle = .informational
                alert.runModal()
            } catch {
                let alert = NSAlert()
                alert.messageText = "CLI Install Failed"
                alert.informativeText = error.localizedDescription
                alert.alertStyle = .warning
                alert.runModal()
            }
        }
    }

    @objc func openSettings() {
        NSApplication.shared.activate(ignoringOtherApps: true)
        for window in NSApplication.shared.windows where window.title.contains("Coulson") {
            window.makeKeyAndOrderFront(nil)
        }
        // Post notification so DashboardView can navigate to settings
        NotificationCenter.default.post(name: .openSettings, object: nil)
    }

    @objc func checkForUpdates() {
        Task { @MainActor in
            updater?.checkForUpdates()
        }
    }
}
