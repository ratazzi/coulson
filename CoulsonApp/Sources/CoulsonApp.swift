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
        NSApplication.shared.setActivationPolicy(.regular)
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        if let iconURL = Bundle.appResources.url(forResource: "AppIcon", withExtension: "png"),
           let icon = NSImage(contentsOf: iconURL)
        {
            NSApplication.shared.applicationIconImage = icon
        }
        NSApplication.shared.activate(ignoringOtherApps: true)
    }

    @MainActor
    func setupStatusBar(vm: CoulsonViewModel, updater: UpdaterController) {
        guard statusItem == nil else { return }
        self.vm = vm
        self.updater = updater

        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let iconURL = Bundle.appResources.url(forResource: "MenuBarIcon", withExtension: "png"),
           let icon2xURL = Bundle.appResources.url(forResource: "MenuBarIcon@2x", withExtension: "png"),
           let rep1x = NSImageRep(contentsOf: iconURL),
           let rep2x = NSImageRep(contentsOf: icon2xURL)
        {
            let image = NSImage(size: NSSize(width: 18, height: 18))
            rep1x.size = NSSize(width: 18, height: 18)
            rep2x.size = NSSize(width: 18, height: 18)
            image.addRepresentation(rep1x)
            image.addRepresentation(rep2x)
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

        refreshTask = Task {
            await vm.refreshAll()
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 1_500_000_000)
                await vm.refreshAll()
            }
        }
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
