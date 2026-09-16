import AppKit

/// Search belongs to this menu tracking session, not to the application or system.
@MainActor
final class MenuSearchController: NSObject, NSSearchFieldDelegate {
    let menuItem = NSMenuItem()
    let field: NSSearchField = MenuSearchField(frame: .zero)
    private weak var menu: NSMenu?
    private var entries: [(AppRecord, NSMenuItem)] = []
    private var emptyItem: NSMenuItem?
    private var needsInitialFocus = false
    private var focusTimer: Timer?
    private var focusAttempts = 0
    private(set) var isTracking = false
    private(set) var defaultResult: NSMenuItem?

    init(menu: NSMenu) {
        self.menu = menu
        super.init()
        let container = MenuSearchContainer(frame: NSRect(x: 0, y: 0, width: 300, height: 40))
        container.onAttach = { [weak self] in self?.requestInitialFocus() }
        field.placeholderString = "Search applications…"
        field.setAccessibilityLabel("Search applications")
        field.sendsSearchStringImmediately = true
        field.sendsWholeSearchString = false
        field.delegate = self
        field.target = self
        field.action = #selector(searchChanged)
        field.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(field)
        NSLayoutConstraint.activate([
            field.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 12),
            field.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -12),
            field.centerYAnchor.constraint(equalTo: container.centerYAnchor),
        ])
        menuItem.view = container
    }

    func configure(entries: [(AppRecord, NSMenuItem)], emptyItem: NSMenuItem) {
        self.entries = entries
        self.emptyItem = emptyItem
        filter("")
    }

    static func matches(_ app: AppRecord, query: String) -> Bool {
        let fields = [app.name, app.domain, app.target.root ?? "", app.target.path ?? ""]
        return query.split(whereSeparator: \.isWhitespace).allSatisfy { term in
            fields.contains { $0.localizedStandardContains(String(term)) }
        }
    }

    func filter(_ query: String) {
        var matches = 0
        var soleMatch: (AppRecord, NSMenuItem)?
        for (app, item) in entries {
            item.isHidden = !Self.matches(app, query: query)
            if !item.isHidden { matches += 1; soleMatch = (app, item) }
        }
        defaultResult = nil
        field.toolTip = nil
        if matches == 1, !query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
           let (app, item) = soleMatch, app.enabled {
            defaultResult = item
            field.toolTip = "Press Return to open \(app.name)"
        }
        emptyItem?.title = entries.isEmpty ? "No apps" : "No matching apps"
        emptyItem?.isHidden = matches > 0
        if isTracking { menu?.update() }
    }

    @objc private func searchChanged() { filter(field.stringValue) }
    func controlTextDidChange(_ notification: Notification) { searchChanged() }

    func control(_ control: NSControl, textView: NSTextView, doCommandBy selector: Selector) -> Bool {
        guard isTracking, !textView.hasMarkedText() else { return false }
        switch NSStringFromSelector(selector) {
        case "insertNewline:": return activateDefaultResult()
        case "insertTab:", "insertBacktab:":
            focusSearch(selectAll: true)
            return true
        case "cancelOperation:":
            if field.stringValue.isEmpty {
                menu?.cancelTracking()
            } else {
                field.stringValue = ""
                textView.string = ""
                filter("")
            }
            return true
        default: return false
        }
    }

    func beginTracking() {
        guard !isTracking else { return }
        isTracking = true
        needsInitialFocus = true
        requestInitialFocus()
    }

    private func requestInitialFocus() {
        focusAttempts = 0
        scheduleFocusAttempt(after: 0)
    }

    /// The menu window is created and shown after menuWillOpen, so a single
    /// attempt can run before the field has a visible window. Retry briefly on
    /// the tracking run-loop mode until the field editor is actually active.
    private func scheduleFocusAttempt(after delay: TimeInterval) {
        focusTimer?.invalidate()
        let timer = Timer(timeInterval: delay, repeats: false) { [weak self] _ in
            MainActor.assumeIsolated { self?.attemptInitialFocus() }
        }
        focusTimer = timer
        for mode in [RunLoop.Mode.default, .eventTracking] { RunLoop.main.add(timer, forMode: mode) }
    }

    private func attemptInitialFocus() {
        guard isTracking, needsInitialFocus else { return }
        focusSearch()
        // The menu window never becomes key while the app is inactive, yet menu
        // tracking still routes keys to its first responder. Treat an active
        // field editor as success rather than waiting for key-window status.
        if let editor = field.currentEditor(), field.window?.firstResponder === editor {
            needsInitialFocus = false
            return
        }
        focusAttempts += 1
        if focusAttempts < 25 { scheduleFocusAttempt(after: 0.04) }
    }

    private func focusSearch(selectAll: Bool = false) {
        guard isTracking, let window = field.window, window.isVisible else { return }
        // Merely assigning firstResponder to an NSMenu window doesn't make it
        // receive keyboard input. The menu window must become key as well.
        window.makeKey()
        if window.makeFirstResponder(field), selectAll { field.selectText(nil) }
    }

    @discardableResult
    func activateDefaultResult() -> Bool {
        guard let item = defaultResult,
              let open = item.submenu?.items.first(where: { $0.action == #selector(AppDelegate.openInBrowser(_:)) }),
              open.isEnabled, let action = open.action else { return false }
        menu?.cancelTracking()
        return NSApplication.shared.sendAction(action, to: open.target, from: open)
    }

    func endTracking() {
        isTracking = false
        needsInitialFocus = false
        focusTimer?.invalidate()
        focusTimer = nil
    }
}

private final class MenuSearchContainer: NSView {
    var onAttach: (() -> Void)?

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        if window != nil { onAttach?() }
    }
}

/// NSTextView only draws its insertion point while the app is active. A search
/// field hosted in a status-item menu never activates the app, so its field
/// editor has to opt in to drawing the caret explicitly.
private final class MenuSearchField: NSSearchField {
    override class var cellClass: AnyClass? {
        get { MenuSearchFieldCell.self }
        set {}
    }
}

private final class MenuSearchFieldCell: NSSearchFieldCell {
    private static let editor: MenuFieldEditor = {
        let editor = MenuFieldEditor()
        editor.isFieldEditor = true
        return editor
    }()

    override func fieldEditor(for controlView: NSView) -> NSTextView? { Self.editor }
}

private final class MenuFieldEditor: NSTextView {
    private var blinkTimer: Timer?
    private var caretOn = true

    /// AppKit draws the insertion point only in a key window of the active
    /// app. Neither holds for a status-item menu, so draw and blink it here.
    private var drawsOwnCaret: Bool {
        guard let window, window.firstResponder === self, !window.isKeyWindow else { return false }
        return isEditable && selectedRange().length == 0
    }

    override func becomeFirstResponder() -> Bool {
        let ok = super.becomeFirstResponder()
        if ok { startBlink() }
        return ok
    }

    override func resignFirstResponder() -> Bool {
        let ok = super.resignFirstResponder()
        if ok { stopBlink() }
        return ok
    }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        if window == nil { stopBlink() }
    }

    override func didChangeText() {
        super.didChangeText()
        showCaret()
    }

    override func setSelectedRanges(_ ranges: [NSValue], affinity: NSSelectionAffinity, stillSelecting: Bool) {
        super.setSelectedRanges(ranges, affinity: affinity, stillSelecting: stillSelecting)
        showCaret()
    }

    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        guard drawsOwnCaret, caretOn, let rect = ownCaretRect() else { return }
        drawInsertionPoint(in: rect, color: insertionPointColor, turnedOn: true)
    }

    private func ownCaretRect() -> NSRect? {
        guard let window else { return nil }
        let screen = firstRect(forCharacterRange: NSRange(location: selectedRange().location, length: 0), actualRange: nil)
        guard screen.height > 0 else { return nil }
        var rect = convert(window.convertFromScreen(screen), from: nil)
        rect.size.width = 1
        return rect
    }

    private func showCaret() {
        caretOn = true
        needsDisplay = true
    }

    private func startBlink() {
        stopBlink()
        caretOn = true
        let timer = Timer(timeInterval: 0.5, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                self.caretOn.toggle()
                self.needsDisplay = true
            }
        }
        blinkTimer = timer
        for mode in [RunLoop.Mode.default, .eventTracking] { RunLoop.main.add(timer, forMode: mode) }
    }

    private func stopBlink() {
        blinkTimer?.invalidate()
        blinkTimer = nil
    }
}
