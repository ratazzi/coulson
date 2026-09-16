import AppKit
import Foundation

enum AppRuntimeState: String, Decodable, CaseIterable {
    case sleeping, starting, ready, failed, disabled, unknown

    var label: String { rawValue.capitalized }

    var color: NSColor {
        switch self {
        case .ready: return .systemGreen
        case .starting: return .systemYellow
        case .failed: return .systemRed
        case .sleeping, .disabled, .unknown: return .systemGray
        }
    }
}

struct AppStatusResponse: Decodable {
    let apps: [AppRuntimeStatus]
}

struct AppRuntimeStatus: Decodable {
    let appID: Int
    let state: AppRuntimeState
    let since: Int64?
    let startedAt: Int64?
    let readyAt: Int64?
    let lastError: AppRuntimeFailure?
    let keepAwake: KeepAwakeStatus?

    enum CodingKeys: String, CodingKey {
        case appID = "app_id"
        case state, since
        case startedAt = "started_at"
        case readyAt = "ready_at"
        case lastError = "last_error"
        case keepAwake = "keep_awake"
    }
}

struct KeepAwakeStatus: Decodable {
    let expiresAt: Int64?

    enum CodingKeys: String, CodingKey {
        case expiresAt = "expires_at"
    }

    func remainingLabel(at date: Date = Date()) -> String? {
        guard let expiresAt else { return "until turned off" }
        let seconds = Double(expiresAt) - date.timeIntervalSince1970
        guard seconds > 0 else { return nil }
        let minutes = Int(ceil(seconds / 60))
        if minutes >= 60 {
            let remainder = minutes % 60
            return remainder == 0 ? "\(minutes / 60)h left" : "\(minutes / 60)h \(remainder)m left"
        }
        return "\(minutes)m left"
    }
}

enum KeepAwakeChoice {
    case oneHour, untilCleared, off

    func parameters(appID: Int) -> [String: Any] {
        switch self {
        case .oneHour: return ["app_id": appID, "mode": "for", "seconds": 3600]
        case .untilCleared: return ["app_id": appID, "mode": "until_cleared"]
        case .off: return ["app_id": appID, "mode": "off"]
        }
    }
}

struct AppRuntimeFailure: Decodable {
    let code: String
    let message: String
    let occurredAt: Int64
    let exitCode: Int?

    enum CodingKeys: String, CodingKey {
        case code, message
        case occurredAt = "occurred_at"
        case exitCode = "exit_code"
    }

    var summary: String {
        guard let exitCode else { return message }
        return "\(message) (exit \(exitCode))"
    }
}
