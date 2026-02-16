import Foundation
import Security

/// Manages the local CA certificate trust installation in macOS Keychain.
@MainActor
final class CertTrustManager {
    private let caCertPath: String

    init() {
        let certsDir = ProcessInfo.processInfo.environment["COULSON_CERTS_DIR"]
            ?? CoulsonViewModel.defaultCertsDir
        self.caCertPath = (certsDir as NSString).appendingPathComponent("ca.crt")
    }

    /// Whether the CA certificate file exists on disk.
    var caCertExists: Bool {
        FileManager.default.fileExists(atPath: caCertPath)
    }

    /// Whether the CA certificate is already trusted in the user's keychain.
    var isCATrusted: Bool {
        guard let certData = try? Data(contentsOf: URL(fileURLWithPath: caCertPath)),
              let cert = SecCertificateCreateWithData(nil, certData as CFData)
        else { return false }

        var trust: SecTrust?
        let policy = SecPolicyCreateBasicX509()
        guard SecTrustCreateWithCertificates(cert, policy, &trust) == errSecSuccess,
              let trust
        else { return false }

        var error: CFError?
        let trusted = SecTrustEvaluateWithError(trust, &error)
        return trusted
    }

    /// Install the CA certificate as trusted using `security add-trusted-cert`.
    /// This will prompt the user for their password via macOS authorization dialog.
    func installCATrust() throws {
        guard caCertExists else {
            throw CertTrustError.noCACert
        }

        // Use `security add-trusted-cert` which triggers macOS password prompt
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        process.arguments = [
            "add-trusted-cert",
            "-r", "trustRoot",     // Trust as root CA
            "-k", NSHomeDirectory() + "/Library/Keychains/login.keychain-db",
            caCertPath,
        ]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()
        process.waitUntilExit()

        if process.terminationStatus != 0 {
            let output = String(
                decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            throw CertTrustError.installFailed(output)
        }
    }

    /// Remove the CA certificate trust from keychain.
    func removeCATrust() throws {
        guard caCertExists else { return }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        process.arguments = [
            "remove-trusted-cert",
            caCertPath,
        ]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()
        process.waitUntilExit()
        // Ignore errors — cert may not be in keychain
    }

    enum CertTrustError: Error, LocalizedError {
        case noCACert
        case installFailed(String)

        var errorDescription: String? {
            switch self {
            case .noCACert:
                return "CA certificate not found. Run the daemon first to generate certificates."
            case .installFailed(let output):
                return "Failed to install CA certificate: \(output)"
            }
        }
    }
}
