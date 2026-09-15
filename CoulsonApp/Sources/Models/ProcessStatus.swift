import Foundation

struct ProcessListResponse: Decodable {
    let processes: [ManagedProcessStatus]

    var runningAppIDs: Set<Int> {
        Set(processes.filter { $0.alive && $0.processType == "web" }.map(\.appID))
    }
}

struct ManagedProcessStatus: Decodable {
    let appID: Int
    let processType: String
    let alive: Bool

    enum CodingKeys: String, CodingKey {
        case appID = "app_id"
        case processType = "process_type"
        case alive
    }
}
