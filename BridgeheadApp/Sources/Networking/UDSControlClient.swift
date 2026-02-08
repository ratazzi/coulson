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

        var buffer = [UInt8](repeating: 0, count: 8192)
        let readCount = read(fd, &buffer, buffer.count)
        guard readCount > 0 else { throw ClientError.emptyResponse }
        let raw = String(decoding: buffer.prefix(readCount), as: UTF8.self)
        let line = raw.split(separator: "\n").first.map(String.init) ?? raw
        guard let json = try JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any] else {
            throw ClientError.invalidResponse
        }

        if let ok = json["ok"] as? Bool, ok, let result = json["result"] as? [String: Any] {
            return result
        }
        throw ClientError.rpcFailed
    }

    enum ClientError: Error, LocalizedError {
        case connectFailed
        case pathTooLong
        case emptyResponse
        case invalidResponse
        case rpcFailed

        var errorDescription: String? {
            switch self {
            case .connectFailed: return "Cannot connect to daemon"
            case .pathTooLong: return "Socket path too long"
            case .emptyResponse: return "Empty response from daemon"
            case .invalidResponse: return "Invalid response from daemon"
            case .rpcFailed: return "RPC request failed"
            }
        }
    }
}
