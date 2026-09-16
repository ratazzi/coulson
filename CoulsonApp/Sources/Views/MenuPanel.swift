import AppKit

/// Wraps AppRecord for use as NSMenuItem.representedObject (requires NSObject)
class AppRecordBox: NSObject {
    let app: AppRecord
    /// State the row was last rendered with, so a live refresh can tell when
    /// the submenu (whose failure section depends on state) must be rebuilt.
    var state: AppRuntimeState
    init(_ app: AppRecord, state: AppRuntimeState) {
        self.app = app
        self.state = state
    }
}

@MainActor
enum MenuBuilder {
    @discardableResult
    static func build(
        menu: NSMenu, vm: CoulsonViewModel, updater: UpdaterController?, target: AppDelegate
    ) -> MenuSearchController {
        let search = MenuSearchController(menu: menu)
        menu.addItem(search.menuItem)
        menu.addItem(.separator())
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
                status.image = statusDot(color: .systemGreen)
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
                status.image = statusDot(color: .systemGray)
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
        var searchableEntries: [(AppRecord, NSMenuItem)] = []
        if !apps.isEmpty {
            for app in apps {
                let box = AppRecordBox(app, state: vm.status(for: app))
                let item = NSMenuItem(title: "", action: nil, keyEquivalent: "")
                item.representedObject = box
                configure(item: item, app: app, state: box.state, vm: vm)
                item.submenu = buildAppSubmenu(box: box, vm: vm, target: target)
                menu.addItem(item)
                searchableEntries.append((app, item))
            }
        }
        let empty = NSMenuItem(title: "No apps", action: nil, keyEquivalent: "")
        empty.isEnabled = false
        menu.addItem(empty)
        search.configure(entries: searchableEntries, emptyItem: empty)

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

        // Keep this entry visible even before Sparkle is ready or in a dev build.
        // A nil action prevents NSMenu auto-validation from enabling it prematurely.
        let canCheck = updater?.canCheckForUpdates == true
        let update = NSMenuItem(
            title: "Check for Updates...",
            action: canCheck ? #selector(AppDelegate.checkForUpdates) : nil,
            keyEquivalent: "")
        update.image = NSImage(systemSymbolName: "arrow.down.circle", accessibilityDescription: nil)
        update.target = canCheck ? target : nil
        update.isEnabled = canCheck
        if !canCheck {
            update.toolTip = DaemonManager.isProductionApp
                ? "Available when the updater is ready."
                : "Updates are available in the installed Coulson.app."
        }
        menu.addItem(update)

        menu.addItem(.separator())

        // Quit
        let quit = NSMenuItem(
            title: "Quit Coulson", action: #selector(NSApplication.terminate(_:)),
            keyEquivalent: "q")
        menu.addItem(quit)
        return search
    }

    /// Update app rows in place while the menu is open. NSMenu asks the
    /// delegate to rebuild only at the start of a tracking session, so status
    /// pulled by the refresh loop would otherwise sit stale until reopened.
    static func refreshApps(menu: NSMenu, vm: CoulsonViewModel, target: AppDelegate) {
        for item in menu.items {
            guard let box = item.representedObject as? AppRecordBox,
                  let app = vm.apps.first(where: { $0.id == box.app.id }) else { continue }
            let state = vm.status(for: app)
            configure(item: item, app: app, state: state, vm: vm)
            guard state != box.state else { continue }
            box.state = state
            item.submenu = buildAppSubmenu(box: box, vm: vm, target: target)
        }
    }

    private static func configure(
        item: NSMenuItem, app: AppRecord, state: AppRuntimeState, vm: CoulsonViewModel
    ) {
        let awakeSuffix = vm.keepAwakeLabel(for: app).map { " · Awake \($0)" } ?? ""
        let title = "\(app.name)\(awakeSuffix)"
        let attributed: NSAttributedString? = state == .disabled
            ? NSAttributedString(string: title, attributes: [.foregroundColor: NSColor.secondaryLabelColor])
            : nil
        let toolTip = vm.statusDetail(for: app)
        guard item.title != title || item.attributedTitle != attributed || item.toolTip != toolTip else { return }
        item.title = title
        item.attributedTitle = attributed
        item.image = statusDot(color: state.color)
        item.toolTip = toolTip
    }

    private static func buildAppSubmenu(
        box: AppRecordBox, vm: CoulsonViewModel, target: AppDelegate
    ) -> NSMenu {
        let sub = NSMenu()
        let app = box.app

        if app.target.type == "managed" && app.enabled {
            let awake = NSMenuItem(title: "Keep Awake", action: nil, keyEquivalent: "")
            let options = NSMenu()
            options.autoenablesItems = false
            if let label = vm.keepAwakeLabel(for: app) {
                let current = NSMenuItem(title: "Keeping awake \(label)", action: nil, keyEquivalent: "")
                current.isEnabled = false
                options.addItem(current)
                options.addItem(.separator())
            }
            for (title, action) in [
                ("For 1 Hour", #selector(AppDelegate.keepAwakeOneHour(_:))),
                ("Until Turned Off", #selector(AppDelegate.keepAwakeUntilCleared(_:))),
                ("Resume Automatic Sleep", #selector(AppDelegate.resumeAutomaticSleep(_:))),
            ] {
                let option = NSMenuItem(title: title, action: action, keyEquivalent: "")
                option.target = target
                option.representedObject = box
                option.isEnabled = vm.isHealthy
                if title == "Resume Automatic Sleep" {
                    option.isEnabled = vm.isHealthy && vm.keepAwakeLabel(for: app) != nil
                }
                options.addItem(option)
            }
            awake.submenu = options
            sub.addItem(awake)
            sub.addItem(.separator())
        }

        if box.state == .failed {
            let failure = NSMenuItem(title: vm.statusDetail(for: app), action: nil, keyEquivalent: "")
            failure.isEnabled = false
            sub.addItem(failure)
            if app.target.type == "managed" && app.enabled {
                let retry = NSMenuItem(title: "Retry Start", action: #selector(AppDelegate.retryStart(_:)), keyEquivalent: "")
                retry.representedObject = box
                retry.target = target
                sub.addItem(retry)
            }
            sub.addItem(.separator())
        }

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

        // LAN Access
        sub.addItem(.separator())

        let lan = NSMenuItem(
            title: app.lanAccess ? "Disable LAN Access" : "Enable LAN Access",
            action: #selector(AppDelegate.toggleLanAccess(_:)), keyEquivalent: "")
        lan.image = NSImage(
            systemSymbolName: app.lanAccess ? "wifi.slash" : "wifi",
            accessibilityDescription: nil)
        lan.representedObject = box
        lan.target = target
        sub.addItem(lan)

        // Logs (only when log file exists)
        let logPath = (vm.runtimeDir as NSString).appendingPathComponent("managed/\(app.name)/web.log")
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

    private static func statusDot(color: NSColor) -> NSImage {
        let size: CGFloat = 8
        let image = NSImage(size: NSSize(width: size, height: size))
        image.lockFocus()
        color.setFill()
        NSBezierPath(ovalIn: NSRect(x: 0, y: 0, width: size, height: size)).fill()
        image.unlockFocus()
        image.isTemplate = false
        return image
    }
}
