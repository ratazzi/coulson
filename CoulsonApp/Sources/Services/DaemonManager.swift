import Foundation
import os.log

private let logger = Logger(subsystem: "ac.hola.coulson", category: "DaemonManager")

/// Manages the Coulson daemon lifecycle via launchd LaunchAgent.
/// Only active in production mode (when running as a .app bundle).
@MainActor
final class DaemonManager: ObservableObject {
    @Published private(set) var isDaemonRunning = false
    @Published private(set) var daemonVersion: String?

    private let serviceLabel = "com.coulson.daemon"
    private let client: UDSControlClient

    /// Whether we're running as a signed .app bundle (production) vs `swift run` (dev).
    static var isProductionApp: Bool {
        Bundle.main.bundleIdentifier == "ac.hola.coulson"
    }

    private var serviceTarget: String {
        "gui/\(getuid())/\(serviceLabel)"
    }

    private var plistPath: String {
        NSHomeDirectory() + "/Library/LaunchAgents/\(serviceLabel).plist"
    }

    /// Path to the daemon binary embedded in the app bundle.
    var daemonBinaryPath: String? {
        Bundle.main.url(forResource: "coulson", withExtension: nil)?.path
    }

    init(client: UDSControlClient) {
        self.client = client
    }

    // MARK: - Status

    /// Check daemon health and version via control socket.
    func checkStatus() async {
        do {
            let result = try client.request(method: "health.ping", params: [:])
            isDaemonRunning = true
            daemonVersion = result["version"] as? String
        } catch {
            isDaemonRunning = false
            daemonVersion = nil
        }
    }

    /// Called from ViewModel's refreshHealth to keep daemon status in sync.
    func updateFromPing(version: String?) {
        isDaemonRunning = version != nil
        daemonVersion = version
    }

    /// Returns the app bundle's embedded daemon version (from VERSION resource or Info.plist).
    var bundledVersion: String? {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String
    }

    /// Whether the running daemon version matches the bundled version.
    var isVersionMatched: Bool {
        guard let running = daemonVersion, let bundled = bundledVersion else { return true }
        return running == bundled
    }

    // MARK: - LaunchAgent Lifecycle

    /// Install the LaunchAgent plist and bootstrap it with launchd.
    func install() throws {
        guard let binary = daemonBinaryPath else {
            throw DaemonError.noBinary
        }

        let plist = buildPlist(daemonPath: binary)
        let plistURL = URL(fileURLWithPath: plistPath)

        // Ensure directory exists
        try FileManager.default.createDirectory(
            at: plistURL.deletingLastPathComponent(),
            withIntermediateDirectories: true)

        // Bootout existing service first (ignore errors if not loaded)
        if FileManager.default.fileExists(atPath: plistPath) {
            _ = try? runLaunchctl(["bootout", serviceTarget])
        }

        try plist.write(to: plistURL, atomically: true, encoding: .utf8)

        // Bootstrap the service
        try runLaunchctl(["bootstrap", "gui/\(getuid())", plistPath])
    }

    /// Uninstall the LaunchAgent: bootout and remove plist.
    func uninstall() throws {
        _ = try? runLaunchctl(["bootout", serviceTarget])
        if FileManager.default.fileExists(atPath: plistPath) {
            try FileManager.default.removeItem(atPath: plistPath)
        }
    }

    /// Start the daemon: re-enable and kickstart.
    func start() throws {
        _ = try? runLaunchctl(["enable", serviceTarget])
        try runLaunchctl(["kickstart", "-p", serviceTarget])
    }

    /// Stop the daemon: disable to prevent auto-restart, then send SIGTERM.
    func stop() throws {
        try runLaunchctl(["disable", serviceTarget])
        _ = try? runLaunchctl(["kill", "SIGTERM", serviceTarget])
    }

    /// Restart the daemon (kill + kickstart, re-enable first).
    func restart() throws {
        _ = try? runLaunchctl(["enable", serviceTarget])
        try runLaunchctl(["kickstart", "-kp", serviceTarget])
    }

    /// Ensure daemon is installed and running. Called on app launch in production mode.
    func ensureRunning() async {
        guard Self.isProductionApp else { return }

        guard let binary = daemonBinaryPath else {
            logger.error("daemon binary not found in app bundle")
            return
        }
        logger.info("daemon binary: \(binary)")

        await checkStatus()

        if !isDaemonRunning {
            do {
                try install()
                logger.info("daemon LaunchAgent installed, waiting for startup")
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                await checkStatus()
                logger.info("daemon running: \(self.isDaemonRunning)")
            } catch {
                logger.error("failed to install daemon: \(error.localizedDescription)")
            }
        } else if !isVersionMatched {
            logger.info("daemon version mismatch (running: \(self.daemonVersion ?? "?"), bundled: \(self.bundledVersion ?? "?")), restarting")
            do {
                try install()
                try restart()
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                await checkStatus()
            } catch {
                logger.error("failed to restart daemon: \(error.localizedDescription)")
            }
        } else {
            logger.info("daemon already running (v\(self.daemonVersion ?? "?"))")
        }
    }

    // MARK: - Private

    private func buildPlist(daemonPath: String) -> String {
        let rtDir = CoulsonViewModel.defaultRuntimeDir
        return """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>\(serviceLabel)</string>
            <key>Program</key>
            <string>\(daemonPath)</string>
            <key>ProgramArguments</key>
            <array>
                <string>\(daemonPath)</string>
                <string>serve</string>
            </array>
            <key>RunAtLoad</key>
            <true/>
            <key>KeepAlive</key>
            <dict>
                <key>SuccessfulExit</key>
                <false/>
            </dict>
            <key>ThrottleInterval</key>
            <integer>5</integer>
            <key>StandardOutPath</key>
            <string>\(rtDir)/daemon.stdout.log</string>
            <key>StandardErrorPath</key>
            <string>\(rtDir)/daemon.stderr.log</string>
            <key>EnvironmentVariables</key>
            <dict>
                <key>COULSON_RUNTIME_DIR</key>
                <string>\(rtDir)</string>
            </dict>
        </dict>
        </plist>
        """
    }

    @discardableResult
    private func runLaunchctl(_ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(decoding: data, as: UTF8.self)
        if process.terminationStatus != 0 {
            throw DaemonError.launchctlFailed(
                args: arguments.joined(separator: " "),
                status: process.terminationStatus,
                output: output)
        }
        return output
    }

    // MARK: - CLI Install

    private static let cliLinkPath = "/usr/local/bin/coulson"

    /// Resolve the coulson binary path: bundle resource first, then cargo build output for dev mode.
    private var cliTargetPath: String? {
        if let path = daemonBinaryPath { return path }
        let fm = FileManager.default
        let cwd = fm.currentDirectoryPath
        for candidate in ["target/release/coulson", "target/debug/coulson"] {
            let path = (cwd as NSString).appendingPathComponent(candidate)
            if fm.isExecutableFile(atPath: path) { return path }
        }
        return nil
    }

    /// Whether the CLI symlink exists and points to the current binary.
    var isCliInstalled: Bool {
        guard let binaryPath = cliTargetPath else { return false }
        let linkURL = URL(fileURLWithPath: Self.cliLinkPath)
        // Check the symlink exists (not just that the resolved target exists)
        let attrs = try? FileManager.default.attributesOfItem(atPath: Self.cliLinkPath)
        guard attrs?[.type] as? FileAttributeType == .typeSymbolicLink else { return false }
        // resolvingSymlinksInPath follows the link and resolves to a canonical absolute path
        let resolved = linkURL.resolvingSymlinksInPath().path
        let expected = URL(fileURLWithPath: binaryPath).resolvingSymlinksInPath().path
        return resolved == expected
    }

    /// Check if an existing file at the CLI link path is safe to overwrite (symlink, not a regular file).
    private func validateExistingCliPath() throws {
        let linkPath = Self.cliLinkPath
        let fm = FileManager.default

        // attributesOfItem uses lstat — works for dangling symlinks unlike fileExists
        guard let attrs = try? fm.attributesOfItem(atPath: linkPath) else { return }
        let fileType = attrs[.type] as? FileAttributeType
        if fileType == .typeSymbolicLink { return }

        throw DaemonError.cliInstallFailed(
            "\(linkPath) already exists and is not a symlink. Please remove it manually.")
    }

    /// Install CLI by creating a symlink at /usr/local/bin/coulson.
    /// Uses AppleScript for administrator privileges if needed.
    func installCLI() throws {
        guard let binaryPath = cliTargetPath else {
            throw DaemonError.noBinary
        }

        let linkPath = Self.cliLinkPath
        let fm = FileManager.default

        try validateExistingCliPath()

        // Try without privilege escalation first
        if fm.isWritableFile(atPath: "/usr/local/bin") {
            try? fm.removeItem(atPath: linkPath)
            try fm.createSymbolicLink(atPath: linkPath, withDestinationPath: binaryPath)
            return
        }

        // Use AppleScript to escalate privileges
        let escaped = binaryPath.replacingOccurrences(of: "'", with: "'\\''")
        let script = "do shell script \"ln -sf '\(escaped)' '\(linkPath)'\" with administrator privileges"
        guard let appleScript = NSAppleScript(source: script) else {
            throw DaemonError.cliInstallFailed("Failed to create AppleScript")
        }
        var error: NSDictionary?
        appleScript.executeAndReturnError(&error)
        if let error {
            let msg = error[NSAppleScript.errorMessage] as? String ?? "Unknown error"
            throw DaemonError.cliInstallFailed(msg)
        }
    }

    /// Uninstall CLI by removing the symlink at /usr/local/bin/coulson.
    func uninstallCLI() throws {
        let linkPath = Self.cliLinkPath
        let fm = FileManager.default

        // attributesOfItem uses lstat — works for dangling symlinks unlike fileExists
        guard let attrs = try? fm.attributesOfItem(atPath: linkPath) else { return }
        let fileType = attrs[.type] as? FileAttributeType
        guard fileType == .typeSymbolicLink else {
            throw DaemonError.cliInstallFailed(
                "\(linkPath) is not a symlink. Please remove it manually.")
        }

        // Try without privilege escalation first
        if fm.isWritableFile(atPath: "/usr/local/bin") {
            try fm.removeItem(atPath: linkPath)
            return
        }

        let script = "do shell script \"rm -f '\(linkPath)'\" with administrator privileges"
        guard let appleScript = NSAppleScript(source: script) else {
            throw DaemonError.cliInstallFailed("Failed to create AppleScript")
        }
        var error: NSDictionary?
        appleScript.executeAndReturnError(&error)
        if let error {
            let msg = error[NSAppleScript.errorMessage] as? String ?? "Unknown error"
            throw DaemonError.cliInstallFailed(msg)
        }
    }

    enum DaemonError: Error, LocalizedError {
        case noBinary
        case launchctlFailed(args: String, status: Int32, output: String)
        case cliInstallFailed(String)

        var errorDescription: String? {
            switch self {
            case .noBinary:
                return "Daemon binary not found in app bundle"
            case .launchctlFailed(let args, let status, let output):
                return "launchctl \(args) failed (\(status)): \(output)"
            case .cliInstallFailed(let msg):
                return "CLI install failed: \(msg)"
            }
        }
    }
}
