import AppKit

/// Wraps AppRecord for use as NSMenuItem.representedObject (requires NSObject)
class AppRecordBox: NSObject {
    let app: AppRecord
    init(_ app: AppRecord) { self.app = app }
}

@MainActor
enum MenuBuilder {
    static func build(
        menu: NSMenu, vm: CoulsonViewModel, updater: UpdaterController?, target: AppDelegate
    ) {
        // Open Dashboard
        let dashboard = NSMenuItem(
            title: "Open Dashboard", action: #selector(AppDelegate.openDashboard),
            keyEquivalent: "d")
        dashboard.image = NSImage(systemSymbolName: "macwindow", accessibilityDescription: nil)
        dashboard.target = target
        menu.addItem(dashboard)

        let webDashboard = NSMenuItem(
            title: "Open Web Dashboard", action: #selector(AppDelegate.openWebDashboard),
            keyEquivalent: "D")
        webDashboard.image = NSImage(
            systemSymbolName: "globe", accessibilityDescription: nil)
        webDashboard.target = target
        menu.addItem(webDashboard)

        menu.addItem(.separator())

        // Daemon status (production mode only)
        if DaemonManager.isProductionApp {
            let dm = vm.daemonManager
            if dm.isDaemonRunning {
                let status = NSMenuItem(
                    title: "Daemon: Running (v\(dm.daemonVersion ?? "?"))",
                    action: nil, keyEquivalent: "")
                status.image = statusDot(enabled: true)
                status.isEnabled = false
                menu.addItem(status)

                let restart = NSMenuItem(
                    title: "Restart Daemon",
                    action: #selector(AppDelegate.restartDaemon),
                    keyEquivalent: "")
                restart.image = NSImage(
                    systemSymbolName: "arrow.clockwise", accessibilityDescription: nil)
                restart.target = target
                menu.addItem(restart)

                let stop = NSMenuItem(
                    title: "Stop Daemon",
                    action: #selector(AppDelegate.stopDaemon),
                    keyEquivalent: "")
                stop.image = NSImage(
                    systemSymbolName: "stop.fill", accessibilityDescription: nil)
                stop.target = target
                menu.addItem(stop)
            } else {
                let status = NSMenuItem(
                    title: "Daemon: Offline", action: nil, keyEquivalent: "")
                status.image = statusDot(enabled: false)
                status.isEnabled = false
                menu.addItem(status)

                let start = NSMenuItem(
                    title: "Start Daemon",
                    action: #selector(AppDelegate.startDaemon),
                    keyEquivalent: "")
                start.image = NSImage(
                    systemSymbolName: "play.fill", accessibilityDescription: nil)
                start.target = target
                menu.addItem(start)
            }

            menu.addItem(.separator())
        }

        // Install CLI (only show when not installed)
        if !vm.daemonManager.isCliInstalled {
            let cli = NSMenuItem(
                title: "Install Command Line Tool...",
                action: #selector(AppDelegate.installCLI),
                keyEquivalent: "")
            cli.image = NSImage(
                systemSymbolName: "terminal", accessibilityDescription: nil)
            cli.target = target
            menu.addItem(cli)
            menu.addItem(.separator())
        }

        // Apps
        let apps = vm.sortedApps
        if apps.isEmpty {
            let empty = NSMenuItem(title: "No apps", action: nil, keyEquivalent: "")
            empty.isEnabled = false
            menu.addItem(empty)
        } else {
            for app in apps {
                let item = NSMenuItem(title: app.name, action: nil, keyEquivalent: "")
                item.image = statusDot(enabled: app.enabled)
                item.submenu = buildAppSubmenu(app: app, vm: vm, target: target)
                menu.addItem(item)
            }
        }

        menu.addItem(.separator())

        // Settings
        let settings = NSMenuItem(
            title: "Settings...",
            action: #selector(AppDelegate.openSettings),
            keyEquivalent: ",")
        settings.image = NSImage(
            systemSymbolName: "gearshape", accessibilityDescription: nil)
        settings.target = target
        menu.addItem(settings)

        // Check for Updates (production mode)
        if DaemonManager.isProductionApp, let updater, updater.canCheckForUpdates {
            let update = NSMenuItem(
                title: "Check for Updates...",
                action: #selector(AppDelegate.checkForUpdates),
                keyEquivalent: "")
            update.image = NSImage(
                systemSymbolName: "arrow.down.circle", accessibilityDescription: nil)
            update.target = target
            menu.addItem(update)
        }

        menu.addItem(.separator())

        // Quit
        let quit = NSMenuItem(
            title: "Quit Coulson", action: #selector(NSApplication.terminate(_:)),
            keyEquivalent: "q")
        menu.addItem(quit)
    }

    private static func buildAppSubmenu(
        app: AppRecord, vm: CoulsonViewModel, target: AppDelegate
    ) -> NSMenu {
        let sub = NSMenu()
        let box = AppRecordBox(app)

        // Open in Browser
        let browser = NSMenuItem(
            title: "Open in Browser",
            action: #selector(AppDelegate.openInBrowser(_:)), keyEquivalent: "")
        browser.image = NSImage(
            systemSymbolName: "safari", accessibilityDescription: nil)
        browser.representedObject = box
        browser.target = target
        browser.isEnabled = app.enabled
        sub.addItem(browser)

        // Copy URL
        let copy = NSMenuItem(
            title: "Copy URL",
            action: #selector(AppDelegate.copyURL(_:)), keyEquivalent: "")
        copy.image = NSImage(
            systemSymbolName: "link", accessibilityDescription: nil)
        copy.representedObject = box
        copy.target = target
        sub.addItem(copy)

        // Copy HTTPS URL
        if vm.httpsPort != nil {
            let copyHTTPS = NSMenuItem(
                title: "Copy HTTPS URL",
                action: #selector(AppDelegate.copyHTTPSURL(_:)), keyEquivalent: "")
            copyHTTPS.image = NSImage(
                systemSymbolName: "lock", accessibilityDescription: nil)
            copyHTTPS.representedObject = box
            copyHTTPS.target = target
            sub.addItem(copyHTTPS)
        }

        // Tunnel
        if vm.globalTunnelConfigured {
            sub.addItem(.separator())

            let tunnel = NSMenuItem(
                title: app.tunnelExposed ? "Disable Tunnel" : "Enable Tunnel",
                action: #selector(AppDelegate.toggleTunnel(_:)), keyEquivalent: "")
            tunnel.image = NSImage(
                systemSymbolName: app.tunnelExposed ? "icloud.slash" : "icloud.and.arrow.up",
                accessibilityDescription: nil)
            tunnel.representedObject = box
            tunnel.target = target
            sub.addItem(tunnel)

            if vm.tunnelURL(for: app) != nil {
                let copyTunnel = NSMenuItem(
                    title: "Copy Tunnel URL",
                    action: #selector(AppDelegate.copyTunnelURL(_:)), keyEquivalent: "")
                copyTunnel.image = NSImage(
                    systemSymbolName: "link.icloud", accessibilityDescription: nil)
                copyTunnel.representedObject = box
                copyTunnel.target = target
                sub.addItem(copyTunnel)
            }
        }

        // Logs (only when log file exists)
        let logPath = (vm.runtimeDir as NSString).appendingPathComponent("managed/\(app.name).log")
        if FileManager.default.fileExists(atPath: logPath) {
            sub.addItem(.separator())

            let logs = NSMenuItem(
                title: "Logs",
                action: #selector(AppDelegate.openLogs(_:)), keyEquivalent: "")
            logs.image = NSImage(
                systemSymbolName: "doc.text", accessibilityDescription: nil)
            logs.representedObject = box
            logs.target = target
            sub.addItem(logs)
        }

        sub.addItem(.separator())

        // Enable / Disable
        let toggle = NSMenuItem(
            title: app.enabled ? "Disable" : "Enable",
            action: #selector(AppDelegate.toggleApp(_:)), keyEquivalent: "")
        toggle.image = NSImage(
            systemSymbolName: app.enabled ? "stop.fill" : "play.fill",
            accessibilityDescription: nil)
        toggle.representedObject = box
        toggle.target = target
        sub.addItem(toggle)

        // Delete
        let delete = NSMenuItem(
            title: "Delete",
            action: #selector(AppDelegate.deleteApp(_:)), keyEquivalent: "")
        delete.image = NSImage(
            systemSymbolName: "trash", accessibilityDescription: nil)
        delete.representedObject = box
        delete.target = target
        sub.addItem(delete)

        return sub
    }

    private static func statusDot(enabled: Bool) -> NSImage {
        let size: CGFloat = 8
        let image = NSImage(size: NSSize(width: size, height: size))
        image.lockFocus()
        (enabled ? NSColor.systemGreen : NSColor.systemGray).setFill()
        NSBezierPath(ovalIn: NSRect(x: 0, y: 0, width: size, height: size)).fill()
        image.unlockFocus()
        image.isTemplate = false
        return image
    }
}
