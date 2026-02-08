import Foundation

struct AppRecord: Decodable, Identifiable, Hashable {
    let id: String
    let name: String
    let kind: String
    let domain: String
    let pathPrefix: String?
    let target: Target
    let timeoutMs: UInt64?
    let enabled: Bool

    enum CodingKeys: String, CodingKey {
        case id, name, kind, domain, target, enabled
        case pathPrefix = "path_prefix"
        case timeoutMs = "timeout_ms"
    }

    var targetLabel: String {
        switch target.type {
        case "tcp":
            return "\(target.host ?? "127.0.0.1"):\(target.port ?? 0)"
        case "unix_socket":
            return target.path ?? "unix socket"
        case "static_dir":
            return target.root ?? "static dir"
        default:
            return target.type
        }
    }

    var primaryURL: String {
        "http://\(domain)/"
    }

    var dashboardURLs: [String] {
        var out = ["http://\(domain)/"]
        if let host = target.host, let port = target.port {
            out.append("http://\(host):\(port)/")
        }
        if domain != "localhost" {
            out.append("http://www.\(domain)/")
        }
        return Array(NSOrderedSet(array: out)) as? [String] ?? out
    }
}

struct Target: Decodable, Hashable {
    let type: String
    let host: String?
    let port: Int?
    let path: String?
    let root: String?
}

struct AppListResponse: Decodable {
    let apps: [AppRecord]
}
