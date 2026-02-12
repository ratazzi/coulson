import AppKit

/// Wraps AppRecord for use as NSMenuItem.representedObject (requires NSObject)
class AppRecordBox: NSObject {
    let app: AppRecord
    init(_ app: AppRecord) { self.app = app }
}

@MainActor
enum MenuBuilder {
    static func build(menu: NSMenu, vm: CoulsonViewModel, target: AppDelegate) {
        // Open Dashboard ⌘D
        let dashboard = NSMenuItem(
            title: "Open Dashboard", action: #selector(AppDelegate.openDashboard),
            keyEquivalent: "d")
        dashboard.image = NSImage(systemSymbolName: "macwindow", accessibilityDescription: nil)
        dashboard.target = target
        menu.addItem(dashboard)

        menu.addItem(.separator())

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

        // Quit ⌘Q
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
        let logPath = "/tmp/coulson/managed/\(app.id).log"
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
