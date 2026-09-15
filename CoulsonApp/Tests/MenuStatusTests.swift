import AppKit
import XCTest
@testable import CoulsonApp

final class MenuStatusTests: XCTestCase {
    @MainActor
    func testEnabledAppWithoutRunningProcessUsesInactiveDot() throws {
        let vm = viewModel()
        vm.isHealthy = true
        vm.apps = [try app(id: 1, enabled: true), try app(id: 2, enabled: false)]

        let menu = NSMenu()
        MenuBuilder.build(menu: menu, vm: vm, updater: nil, target: AppDelegate())
        let enabledDot = try XCTUnwrap(menu.item(withTitle: "demo-1")?.image?.tiffRepresentation)
        let disabledDot = try XCTUnwrap(menu.item(withTitle: "demo-2")?.image?.tiffRepresentation)
        XCTAssertEqual(enabledDot, disabledDot, "Enabling an app does not mean its process is running")
    }

    @MainActor
    func testMenuDotTracksRunningProcessAndDaemonHealth() throws {
        let vm = viewModel()
        vm.isHealthy = true
        vm.apps = [try app(id: 1, enabled: true), try app(id: 2, enabled: false)]
        vm.runningAppIDs = [1, 2]
        let menu = NSMenu()
        MenuBuilder.build(menu: menu, vm: vm, updater: nil, target: AppDelegate())
        let runningDot = try XCTUnwrap(menu.item(withTitle: "demo-1")?.image?.tiffRepresentation)
        let disabledDot = try XCTUnwrap(menu.item(withTitle: "demo-2")?.image?.tiffRepresentation)
        XCTAssertNotEqual(runningDot, disabledDot)

        vm.isHealthy = false
        let offlineMenu = NSMenu()
        MenuBuilder.build(menu: offlineMenu, vm: vm, updater: nil, target: AppDelegate())
        XCTAssertEqual(offlineMenu.item(withTitle: "demo-1")?.image?.tiffRepresentation, disabledDot)
    }

    func testProcessSnapshotRequiresLiveWebProcess() throws {
        let json = #"{"processes":[{"app_id":1,"process_type":"web","alive":true},{"app_id":1,"process_type":"worker","alive":false},{"app_id":2,"process_type":"web","alive":false},{"app_id":2,"process_type":"worker","alive":true},{"app_id":3,"process_type":"worker","alive":true}]}"#
        let snapshot = try JSONDecoder().decode(ProcessListResponse.self, from: Data(json.utf8))
        XCTAssertEqual(snapshot.runningAppIDs, [1])
    }

    @MainActor
    func testFailedProcessRefreshClearsPreviousRunningState() async throws {
        let vm = viewModel()
        vm.isHealthy = true
        vm.runningAppIDs = [1]
        let record = try app(id: 1, enabled: true)
        XCTAssertTrue(vm.isAppRunning(record))
        await vm.refreshProcesses()
        XCTAssertFalse(vm.isAppRunning(record))
        XCTAssertTrue(vm.runningAppIDs.isEmpty)
    }

    @MainActor
    func testStaticFilesAndUnmonitoredExternalBackends() throws {
        let vm = viewModel()
        vm.isHealthy = true
        XCTAssertTrue(vm.isAppRunning(try app(id: 1, enabled: true, targetType: "static_dir")))
        XCTAssertFalse(vm.isAppRunning(try app(id: 2, enabled: false, targetType: "static_dir")))
        for type in ["tcp", "unix_socket"] {
            XCTAssertFalse(vm.isAppRunning(try app(id: 3, enabled: true, targetType: type)))
        }
        vm.isHealthy = false
        XCTAssertFalse(vm.isAppRunning(try app(id: 1, enabled: true, targetType: "static_dir")))
    }

    @MainActor
    private func viewModel() -> CoulsonViewModel {
        CoulsonViewModel(client: UDSControlClient(socketPath: "/tmp/coulson-missing-\(UUID().uuidString).sock"))
    }

    private func app(id: Int, enabled: Bool, targetType: String = "managed") throws -> AppRecord {
        let json = """
        {"id":\(id),"name":"demo-\(id)","kind":"asgi","domain":"demo-\(id).coulson.local",
         "target":{"type":"\(targetType)","kind":"asgi"},"cors_enabled":false,"spa_rewrite":false,
         "lan_access":false,"tunnel_exposed":false,"tunnel_mode":"none","enabled":\(enabled)}
        """
        return try JSONDecoder().decode(AppRecord.self, from: Data(json.utf8))
    }
}
