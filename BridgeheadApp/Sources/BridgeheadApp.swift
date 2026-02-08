import AppKit
import SwiftUI

@main
struct BridgeheadAppMain: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @StateObject private var vm = BridgeheadViewModel()

    var body: some Scene {
        WindowGroup("Bridgehead") {
            DashboardView()
                .environmentObject(vm)
                .frame(minWidth: 360, minHeight: 320)
        }
        .defaultSize(width: 420, height: 520)
        .windowResizability(.contentMinSize)

        MenuBarExtra("Bridgehead", systemImage: "point.3.connected.trianglepath.dotted") {
            MenuPanel()
                .environmentObject(vm)
        }
        .menuBarExtraStyle(.menu)
    }
}

class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationWillFinishLaunching(_ notification: Notification) {
        NSApplication.shared.setActivationPolicy(.regular)
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApplication.shared.activate(ignoringOtherApps: true)
    }
}
