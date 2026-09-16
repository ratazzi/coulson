import AppKit
import XCTest
@testable import CoulsonApp

final class MenuSearchTests: XCTestCase {
    private func app(_ id: Int, _ name: String, root: String, enabled: Bool = true) throws -> AppRecord {
        let value: [String: Any] = [
            "id": id, "name": name, "domain": "\(name).coulson.local", "kind": "asgi",
            "target": ["type": "managed", "root": root, "kind": "asgi"],
            "enabled": enabled, "cors_enabled": false, "spa_rewrite": false,
            "lan_access": false, "tunnel_exposed": false, "tunnel_mode": "none",
        ]
        return try JSONDecoder().decode(AppRecord.self, from: JSONSerialization.data(withJSONObject: value))
    }

    @MainActor
    func testTextEditorReturnInvokesTheUniqueResult() throws {
        let vm = CoulsonViewModel(client: UDSControlClient(socketPath: "/tmp/unused-menu-search.sock"))
        vm.apps = [try app(1, "alpha", root: "/projects/alpha")]
        let menu = NSMenu()
        let search = MenuBuilder.build(menu: menu, vm: vm, updater: nil, target: AppDelegate())
        let target = OpenTarget()
        let open = try XCTUnwrap(menu.item(withTitle: "alpha — Unknown")?.submenu?.item(withTitle: "Open in Browser"))
        open.target = target
        search.beginTracking()
        defer { search.endTracking() }
        search.field.stringValue = "alpha"
        search.filter("alpha")
        XCTAssertTrue(search.control(search.field, textView: NSTextView(), doCommandBy: NSSelectorFromString("insertNewline:")))
        XCTAssertEqual(target.receivedID, 1)
    }

    @MainActor
    func testTextEditorKeepsCompositionAndHandlesEscape() throws {
        final class ComposingTextView: NSTextView {
            override func hasMarkedText() -> Bool { true }
        }
        let search = MenuSearchController(menu: NSMenu())
        search.beginTracking()
        defer { search.endTracking() }
        XCTAssertFalse(search.control(search.field, textView: ComposingTextView(), doCommandBy: NSSelectorFromString("insertNewline:")))
        search.field.stringValue = "query"
        let editor = NSTextView()
        editor.string = "query"
        XCTAssertTrue(search.control(search.field, textView: editor, doCommandBy: NSSelectorFromString("cancelOperation:")))
        XCTAssertEqual(search.field.stringValue, "")
        XCTAssertEqual(editor.string, "")
        XCTAssertTrue(search.control(search.field, textView: editor, doCommandBy: NSSelectorFromString("insertTab:")))
    }

    @MainActor
    func testUpdateEntryIsEnabledWhenUpdaterIsReady() throws {
        let vm = CoulsonViewModel(client: UDSControlClient(socketPath: "/tmp/unused-menu-search.sock"))
        let updater = UpdaterController()
        updater.canCheckForUpdates = true
        let menu = NSMenu()
        MenuBuilder.build(menu: menu, vm: vm, updater: updater, target: AppDelegate())
        let item = try XCTUnwrap(menu.item(withTitle: "Check for Updates..."))
        XCTAssertTrue(item.isEnabled)
        XCTAssertEqual(item.action, #selector(AppDelegate.checkForUpdates))
    }

    @MainActor
    func testUniqueResultIsTheReturnTargetWithoutOpeningAnythingWhileTyping() throws {
        let vm = CoulsonViewModel(client: UDSControlClient(socketPath: "/tmp/unused-menu-search.sock"))
        vm.apps = [try app(1, "alpha", root: "/projects/alpha"), try app(2, "alphabet", root: "/projects/alphabet")]
        let menu = NSMenu()
        let search = MenuBuilder.build(menu: menu, vm: vm, updater: nil, target: AppDelegate())
        let target = OpenTarget()
        let item = try XCTUnwrap(menu.item(withTitle: "alpha — Unknown"))
        let open = try XCTUnwrap(item.submenu?.item(withTitle: "Open in Browser"))
        open.target = target
        search.filter("alpha")
        XCTAssertNil(search.defaultResult)
        search.filter("alpha.coulson")
        XCTAssertTrue(search.defaultResult === item)
        XCTAssertEqual(search.field.toolTip, "Press Return to open alpha")
        XCTAssertNil(target.receivedID)
        XCTAssertTrue(search.activateDefaultResult())
        XCTAssertEqual(target.receivedID, 1)
        search.filter("")
        XCTAssertNil(search.defaultResult)
        XCTAssertNil(search.field.toolTip)
    }

    @MainActor
    func testReturnPrefersTheHighlightedRowOverTheSearchMatch() throws {
        let vm = CoulsonViewModel(client: UDSControlClient(socketPath: "/tmp/unused-menu-search.sock"))
        vm.apps = [try app(1, "alpha", root: "/projects/alpha"), try app(2, "beta", root: "/projects/beta")]
        let menu = NSMenu()
        let search = MenuBuilder.build(menu: menu, vm: vm, updater: nil, target: AppDelegate())
        let target = OpenTarget()
        let beta = try XCTUnwrap(menu.item(withTitle: "beta — Unknown"))
        for row in [try XCTUnwrap(menu.item(withTitle: "alpha — Unknown")), beta] {
            try XCTUnwrap(row.submenu?.item(withTitle: "Open in Browser")).target = target
        }
        // Empty query: nothing to fall back to, the highlighted row still opens.
        XCTAssertNil(search.defaultResult)
        XCTAssertFalse(search.activateReturnTarget(highlighted: nil))
        XCTAssertTrue(search.activateReturnTarget(highlighted: beta))
        XCTAssertEqual(target.receivedID, 2)
        // A highlighted row wins while the query still shows it.
        search.filter("projects")
        XCTAssertNil(search.defaultResult)
        target.receivedID = nil
        XCTAssertTrue(search.activateReturnTarget(highlighted: beta))
        XCTAssertEqual(target.receivedID, 2)
        // A highlight hidden by the query falls back to the unique match.
        search.filter("alpha.coulson")
        XCTAssertTrue(beta.isHidden)
        XCTAssertTrue(search.activateReturnTarget(highlighted: beta))
        XCTAssertEqual(target.receivedID, 1)
    }

    @MainActor
    func testDisabledUniqueResultCannotBeOpenedWithReturn() throws {
        let vm = CoulsonViewModel(client: UDSControlClient(socketPath: "/tmp/unused-menu-search.sock"))
        vm.apps = [try app(1, "alpha", root: "/projects/alpha", enabled: false)]
        let menu = NSMenu()
        let search = MenuBuilder.build(menu: menu, vm: vm, updater: nil, target: AppDelegate())
        search.filter("alpha")
        XCTAssertNil(search.defaultResult)
        XCTAssertFalse(search.activateDefaultResult())
    }

    @MainActor
    func testClosingMenuBeforeViewAttachesDoesNotStealFocus() throws {
        let menu = NSMenu()
        let search = MenuSearchController(menu: menu)
        search.beginTracking()
        defer { search.endTracking() }
        RunLoop.main.run(until: Date().addingTimeInterval(0.01))
        XCTAssertNil(search.field.window)
        search.endTracking()
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 300, height: 40),
                              styleMask: .borderless, backing: .buffered, defer: false)
        window.contentView = search.menuItem.view
        RunLoop.main.run(until: Date().addingTimeInterval(0.01))
        XCTAssertNil(search.field.currentEditor())
        XCTAssertFalse(window.firstResponder === search.field)
    }

    @MainActor
    func testUpdateEntryRemainsVisibleWhenUpdaterIsUnavailable() throws {
        let vm = CoulsonViewModel(client: UDSControlClient(socketPath: "/tmp/unused-menu-search.sock"))
        let menu = NSMenu()
        let search = MenuBuilder.build(menu: menu, vm: vm, updater: nil, target: AppDelegate())
        let update = try XCTUnwrap(menu.item(withTitle: "Check for Updates..."))
        XCTAssertFalse(update.isEnabled)
        XCTAssertFalse(update.isHidden)
        search.filter("no matches")
        XCTAssertFalse(update.isHidden)
    }

    @MainActor
    func testFilteringPreservesNativeSubmenusAndManagementItems() throws {
        let vm = CoulsonViewModel(client: UDSControlClient(socketPath: "/tmp/unused-menu-search.sock"))
        vm.apps = [try app(1, "alpha", root: "/projects/python"), try app(2, "beta", root: "/projects/web")]
        let menu = NSMenu()
        let search = MenuBuilder.build(menu: menu, vm: vm, updater: nil, target: AppDelegate())
        let alpha = try XCTUnwrap(menu.item(withTitle: "alpha — Unknown"))
        let beta = try XCTUnwrap(menu.item(withTitle: "beta — Unknown"))
        let submenu = alpha.submenu
        search.filter("ALPHA")
        XCTAssertFalse(alpha.isHidden)
        XCTAssertTrue(beta.isHidden)
        XCTAssertTrue(alpha.submenu === submenu)
        XCTAssertFalse(try XCTUnwrap(menu.item(withTitle: "Open Dashboard")).isHidden)
        search.filter("beta.coulson")
        XCTAssertTrue(alpha.isHidden)
        XCTAssertFalse(beta.isHidden)
        search.filter("projects python")
        XCTAssertFalse(alpha.isHidden)
        XCTAssertTrue(beta.isHidden)
        search.filter("not-present")
        XCTAssertFalse(try XCTUnwrap(menu.item(withTitle: "No matching apps")).isHidden)
        search.filter("")
        XCTAssertFalse(alpha.isHidden)
        XCTAssertFalse(beta.isHidden)
        XCTAssertTrue(try XCTUnwrap(menu.item(withTitle: "No matching apps")).isHidden)
    }

    @MainActor
    func testEmptyCatalogAndReopeningResetSearch() throws {
        let vm = CoulsonViewModel(client: UDSControlClient(socketPath: "/tmp/unused-menu-search.sock"))
        let menu = NSMenu()
        let first = MenuBuilder.build(menu: menu, vm: vm, updater: nil, target: AppDelegate())
        first.field.stringValue = "old query"
        first.filter(first.field.stringValue)
        XCTAssertFalse(try XCTUnwrap(menu.item(withTitle: "No apps")).isHidden)
        first.beginTracking()
        XCTAssertTrue(first.isTracking)
        XCTAssertTrue(first.field.isEnabled)
        first.endTracking()
        XCTAssertFalse(first.isTracking)
        menu.removeAllItems()
        let reopened = MenuBuilder.build(menu: menu, vm: vm, updater: nil, target: AppDelegate())
        XCTAssertEqual(reopened.field.stringValue, "")
        XCTAssertFalse(reopened.isTracking)
    }
}

@MainActor
private final class OpenTarget: NSObject {
    var receivedID: Int?
    @objc func openInBrowser(_ sender: NSMenuItem) {
        receivedID = (sender.representedObject as? AppRecordBox)?.app.id
    }
}
