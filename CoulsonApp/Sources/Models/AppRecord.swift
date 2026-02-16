import Foundation

struct AppRecord: Decodable, Identifiable, Hashable {
    let id: Int
    let name: String
    let kind: String
    let domain: String
    let pathPrefix: String?
    let target: Target
    let timeoutMs: UInt64?
    let corsEnabled: Bool
    let basicAuthUser: String?
    let basicAuthPass: String?
    let spaRewrite: Bool
    let listenPort: Int?
    let tunnelExposed: Bool
    let tunnelMode: String
    let tunnelUrl: String?
    let appTunnelDomain: String?
    let enabled: Bool

    enum CodingKeys: String, CodingKey {
        case id, name, kind, domain, target, enabled
        case pathPrefix = "path_prefix"
        case timeoutMs = "timeout_ms"
        case corsEnabled = "cors_enabled"
        case basicAuthUser = "basic_auth_user"
        case basicAuthPass = "basic_auth_pass"
        case spaRewrite = "spa_rewrite"
        case listenPort = "listen_port"
        case tunnelExposed = "tunnel_exposed"
        case tunnelMode = "tunnel_mode"
        case tunnelUrl = "tunnel_url"
        case appTunnelDomain = "app_tunnel_domain"
    }

    var kindLabel: String {
        switch target.type {
        case "tcp": return "proxy"
        case "unix_socket": return "unix socket"
        case "static_dir": return "static"
        default: return kind
        }
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

    func primaryURL(proxyPort: Int?) -> String {
        let portSuffix = (proxyPort != nil && proxyPort != 80) ? ":\(proxyPort!)" : ""
        return "http://\(domain)\(portSuffix)/"
    }

    func httpsURL(httpsPort: Int?) -> String? {
        guard let port = httpsPort else { return nil }
        let portSuffix = port != 443 ? ":\(port)" : ""
        return "https://\(domain)\(portSuffix)/"
    }

    func dashboardURLs(proxyPort: Int?, httpsPort: Int?) -> [String] {
        var out = [primaryURL(proxyPort: proxyPort)]
        if let https = httpsURL(httpsPort: httpsPort) {
            out.append(https)
        }
        if let host = target.host, let port = target.port {
            out.append("http://\(host):\(port)/")
        }
        return out
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
