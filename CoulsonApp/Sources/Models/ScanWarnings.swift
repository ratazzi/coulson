import Foundation

struct ScanWarningsFile: Decodable {
    let updatedAt: Int64
    let scan: ScanSummary

    enum CodingKeys: String, CodingKey {
        case updatedAt = "updated_at"
        case scan
    }
}

struct ScanSummary: Decodable {
    let conflictDomains: [String]
    let parseWarnings: [String]
    let warningCount: Int
    let hasIssues: Bool

    enum CodingKeys: String, CodingKey {
        case conflictDomains = "conflict_domains"
        case parseWarnings = "parse_warnings"
        case warningCount = "warning_count"
        case hasIssues = "has_issues"
    }
}

struct WarningsResponse: Decodable {
    let warnings: ScanWarningsFile?
}
