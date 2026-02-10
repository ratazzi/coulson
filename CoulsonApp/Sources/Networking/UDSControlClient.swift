import Foundation
import Darwin

struct UDSControlClient {
    let socketPath: String

    func request(method: String, params: [String: Any]) throws -> [String: Any] {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw ClientError.connectFailed }
        defer { close(fd) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let maxLen = MemoryLayout.size(ofValue: addr.sun_path)
        let utf8 = socketPath.utf8
        guard utf8.count < maxLen else { throw ClientError.pathTooLong }
        withUnsafeMutablePointer(to: &addr.sun_path) {
            $0.withMemoryRebound(to: CChar.self, capacity: maxLen) { ptr in
                memset(ptr, 0, maxLen)
                _ = socketPath.withCString { cs in
                    strncpy(ptr, cs, maxLen - 1)
                }
            }
        }

        let len = socklen_t(MemoryLayout<sa_family_t>.size + socketPath.utf8.count + 1)
        let connectResult = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { ptr in
                connect(fd, ptr, len)
            }
        }
        guard connectResult == 0 else { throw ClientError.connectFailed }

        // Set read timeout so we don't block forever if daemon stalls.
        var tv = timeval(tv_sec: 5, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        let reqID = "swift-\(UUID().uuidString)"
        let payload: [String: Any] = [
            "request_id": reqID,
            "method": method,
            "params": params,
        ]
        let data = try JSONSerialization.data(withJSONObject: payload, options: [])
        data.withUnsafeBytes { bytes in
            guard let base = bytes.bindMemory(to: UInt8.self).baseAddress else { return }
            _ = write(fd, base, data.count)
            var nl = UInt8(ascii: "\n")
            _ = write(fd, &nl, 1)
        }
        // Signal we're done writing so the server's reader returns EOF
        // instead of blocking on next_line(), preventing broken pipe on close.
        shutdown(fd, SHUT_WR)

        // Read until we get a complete NDJSON line (terminated by \n).
        var accumulated = Data()
        var chunk = [UInt8](repeating: 0, count: 16384)
        while true {
            let n = read(fd, &chunk, chunk.count)
            if n <= 0 { break }
            accumulated.append(contentsOf: chunk.prefix(n))
            if accumulated.contains(UInt8(ascii: "\n")) { break }
        }
        guard !accumulated.isEmpty else { throw ClientError.emptyResponse }
        let raw = String(decoding: accumulated, as: UTF8.self)
        let line = raw.split(separator: "\n").first.map(String.init) ?? raw
        guard let json = try JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any] else {
            throw ClientError.invalidResponse
        }

        if let ok = json["ok"] as? Bool, ok, let result = json["result"] as? [String: Any] {
            return result
        }
        if let err = json["error"] as? [String: Any], let msg = err["message"] as? String {
            throw ClientError.rpcFailed(msg)
        }
        throw ClientError.rpcFailed("unknown error")
    }

    enum ClientError: Error, LocalizedError {
        case connectFailed
        case pathTooLong
        case emptyResponse
        case invalidResponse
        case rpcFailed(String)

        var errorDescription: String? {
            switch self {
            case .connectFailed: return "Cannot connect to daemon"
            case .pathTooLong: return "Socket path too long"
            case .emptyResponse: return "Empty response from daemon"
            case .invalidResponse: return "Invalid response from daemon"
            case .rpcFailed(let msg): return msg
            }
        }
    }
}
