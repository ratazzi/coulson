import XCTest
@testable import CoulsonApp

final class LocalWebURLsTests: XCTestCase {
    func testPreferredURLsForDashboardAndApps() {
        let cases: [(LocalWebURLs, String, String)] = [
            (.init(httpPort: 18080, httpsPort: 18443,
                   useDefaultHttpPort: true, useDefaultHttpsPort: true), "https", ""),
            (.init(httpPort: 18080, httpsPort: 18443), "https", ":18443"),
            (.init(httpPort: 18080, httpsPort: 18443,
                   useDefaultHttpPort: true), "https", ":18443"),
            (.init(httpPort: 18080, httpsPort: 18443,
                   useDefaultHttpsPort: true), "https", ""),
            (.init(httpPort: 80, httpsPort: 443), "https", ""),
            (.init(httpPort: 18080, useDefaultHttpPort: true), "http", ""),
            (.init(httpPort: 18080), "http", ":18080"),
            (.init(httpPort: 80), "http", ""),
            (.init(httpPort: 28080, httpsPort: 28443), "https", ":28443"),
        ]
        for (urls, scheme, port) in cases {
            for domain in ["coulson.local", "demo.coulson.local"] {
                XCTAssertEqual(urls.preferredURL(for: domain), "\(scheme)://\(domain)\(port)/")
            }
        }
    }

    func testDisablingHTTPSFallsBackToHTTP() {
        var urls = LocalWebURLs(httpPort: 18080, httpsPort: 18443,
                                useDefaultHttpPort: true, useDefaultHttpsPort: true)
        XCTAssertEqual(urls.preferredURL(for: "demo.coulson.local"), "https://demo.coulson.local/")
        urls.httpsPort = nil
        XCTAssertEqual(urls.preferredURL(for: "demo.coulson.local"), "http://demo.coulson.local/")
    }

    func testAppDetailsListPreferredURLFirst() throws {
        let json = #"{"id":1,"name":"demo","kind":"static","domain":"demo.coulson.local","target":{"type":"tcp","host":"127.0.0.1","port":3000},"cors_enabled":false,"spa_rewrite":false,"lan_access":false,"tunnel_exposed":false,"tunnel_mode":"none","enabled":true}"#
        let app = try JSONDecoder().decode(AppRecord.self, from: Data(json.utf8))
        XCTAssertEqual(
            app.dashboardURLs(proxyPort: 18080, httpsPort: 18443,
                              useDefaultHttpPort: true, useDefaultHttpsPort: true),
            ["https://demo.coulson.local/", "http://demo.coulson.local/", "http://127.0.0.1:3000/"]
        )
        XCTAssertEqual(
            app.dashboardURLs(proxyPort: 18080, httpsPort: nil),
            ["http://demo.coulson.local:18080/", "http://127.0.0.1:3000/"]
        )
    }
}
