import Foundation

struct LocalWebURLs {
    var httpPort: Int?
    var httpsPort: Int?
    var useDefaultHttpPort = false
    var useDefaultHttpsPort = false

    func preferredURL(for domain: String) -> String {
        httpsURL(for: domain) ?? httpURL(for: domain)
    }

    func httpURL(for domain: String) -> String {
        let port = httpPort ?? 80
        let suffix = port == 80 || useDefaultHttpPort ? "" : ":\(port)"
        return "http://\(domain)\(suffix)/"
    }

    func httpsURL(for domain: String) -> String? {
        guard let port = httpsPort else { return nil }
        let suffix = port == 443 || useDefaultHttpsPort ? "" : ":\(port)"
        return "https://\(domain)\(suffix)/"
    }
}
