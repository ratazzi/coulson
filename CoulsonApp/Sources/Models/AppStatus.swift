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

    enum CodingKeys: String, CodingKey {
        case appID = "app_id"
        case state, since
        case startedAt = "started_at"
        case readyAt = "ready_at"
        case lastError = "last_error"
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
