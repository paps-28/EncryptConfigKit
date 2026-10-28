import Foundation
import OSLog

@MainActor
enum AppAttestLog {
    static let flow = Logger(subsystem: Bundle.main.bundleIdentifier ?? "com.encryptKeyTest", category: "AppAttest")
    static let network = Logger(subsystem: Bundle.main.bundleIdentifier ?? "com.encryptKeyTest", category: "AppAttest.HTTP")

    static func failure(_ error: Error, stage: String) {
        if case APIError.httpError(let status) = error {
            flow.error("stage=\(stage, privacy: .public) failed http_status=\(status)")
        } else {
            // Error descriptions/userInfo can contain request data. Only record domain and code.
            let nsError = error as NSError
            flow.error("stage=\(stage, privacy: .public) failed domain=\(nsError.domain, privacy: .public) code=\(nsError.code)")
        }
    }
}
