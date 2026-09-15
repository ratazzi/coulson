import AppKit
import XCTest
@testable import CoulsonApp

final class MenuStatusTests: XCTestCase {
    @MainActor
    func testMenuDisplaysEveryDaemonState() throws {
        let vm = viewModel()
        vm.isHealthy = true
        vm.apps = [try app()]
        var dots: [AppRuntimeState: Data] = [:]
        for state in AppRuntimeState.allCases {
            vm.appStatuses = [1: try status(state)]
            let menu = NSMenu()
            MenuBuilder.build(menu: menu, vm: vm, updater: nil, target: AppDelegate())
            let item = try XCTUnwrap(menu.item(withTitle: "demo — \(state.label)"))
            dots[state] = try XCTUnwrap(item.image?.tiffRepresentation)
            if state == .disabled { XCTAssertNotNil(item.attributedTitle) }
        }
        for state in AppRuntimeState.allCases where state != .ready {
            XCTAssertNotEqual(dots[state], dots[.ready], "Only ready apps should have green dots")
        }
        XCTAssertNotEqual(dots[.starting], dots[.failed])
        XCTAssertEqual(dots[.sleeping], dots[.unknown])
    }

    @MainActor
    func testFailedMenuIncludesReasonAndRetry() throws {
        let vm = viewModel()
        vm.isHealthy = true
        vm.apps = [try app()]
        vm.appStatuses = [1: try status(.failed)]
        let menu = NSMenu()
        MenuBuilder.build(menu: menu, vm: vm, updater: nil, target: AppDelegate())
        let item = try XCTUnwrap(menu.item(withTitle: "demo — Failed"))
        XCTAssertEqual(item.toolTip, "Primary process exited unexpectedly (exit 7)")
        XCTAssertNotNil(item.submenu?.item(withTitle: "Retry Start"))
    }

    @MainActor
    func testUnavailableDaemonOverridesCachedReadyState() throws {
        let vm = viewModel()
        vm.appStatuses = [1: try status(.ready)]
        XCTAssertEqual(vm.status(for: try app()), .unknown)
        vm.isHealthy = true
        XCTAssertEqual(vm.status(for: try app()), .ready)
    }

    @MainActor
    func testFailedStatusRefreshDoesNotGuessFromEnabledFlag() async throws {
        let vm = viewModel()
        vm.isHealthy = true
        vm.appStatuses = [1: try status(.ready)]
        await vm.refreshAppStatuses()
        XCTAssertEqual(vm.status(for: try app()), .unknown)
        XCTAssertTrue(vm.appStatuses.isEmpty)
    }

    func testDecodeDaemonStatusWithFailureAndTimestamps() throws {
        let json = #"{"apps":[{"app_id":1,"name":"demo","domain":"demo.coulson.local","state":"failed","since":103,"started_at":100,"ready_at":101,"last_error":{"code":"process_exited","message":"Primary process exited unexpectedly","occurred_at":103,"exit_code":7}}]}"#
        let response = try JSONDecoder().decode(AppStatusResponse.self, from: Data(json.utf8))
        XCTAssertEqual(response.apps.first?.state, .failed)
        XCTAssertEqual(response.apps.first?.startedAt, 100)
        XCTAssertEqual(response.apps.first?.readyAt, 101)
        XCTAssertEqual(response.apps.first?.lastError?.exitCode, 7)
    }

    @MainActor
    func testSubtitleCountsReadyAppsOnly() throws {
        let vm = viewModel()
        vm.isHealthy = true
        vm.apps = [try app()]
        vm.appStatuses = [1: try status(.starting)]
        XCTAssertEqual(vm.subtitle, "0/1 ready")
        vm.appStatuses = [1: try status(.ready)]
        XCTAssertEqual(vm.subtitle, "1/1 ready")
    }

    private func status(_ state: AppRuntimeState) throws -> AppRuntimeStatus {
        let json = """
        {"app_id":1,"state":"\(state.rawValue)","since":100,"started_at":100,"ready_at":null,
         "last_error":{"code":"process_exited","message":"Primary process exited unexpectedly","occurred_at":103,"exit_code":7}}
        """
        return try JSONDecoder().decode(AppRuntimeStatus.self, from: Data(json.utf8))
    }

    @MainActor
    private func viewModel() -> CoulsonViewModel {
        CoulsonViewModel(client: UDSControlClient(socketPath: "/tmp/coulson-missing-\(UUID().uuidString).sock"))
    }

    private func app() throws -> AppRecord {
        let json = #"{"id":1,"name":"demo","kind":"asgi","domain":"demo.coulson.local","target":{"type":"managed","kind":"asgi"},"cors_enabled":false,"spa_rewrite":false,"lan_access":false,"tunnel_exposed":false,"tunnel_mode":"none","enabled":true}"#
        return try JSONDecoder().decode(AppRecord.self, from: Data(json.utf8))
    }
}
