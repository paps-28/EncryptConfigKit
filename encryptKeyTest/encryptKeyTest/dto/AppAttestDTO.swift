import Foundation

nonisolated enum AppAttestPurpose: String, Encodable, Sendable {
    case attestation = "ATTESTATION"
    case assertion = "ASSERTION"
}

nonisolated struct AppAttestChallengeRequest: Encodable, Sendable {
    let keyId: String
    let purpose: AppAttestPurpose
}

nonisolated struct AppAttestChallengeResponse: Decodable, Sendable {
    let challengeId: String
    let challenge: String
    let expiresAt: String

    func decodedChallenge() throws -> Data {
        guard !challengeId.isEmpty,
              let data = Data(base64Encoded: challenge), data.count == 32 else {
            throw RemoteKeyProviderError.invalidChallenge
        }
        return data
    }
}

nonisolated struct AppAttestRegistrationRequest: Encodable, Sendable {
    let keyId: String
    let challengeId: String
    let attestationObject: String
}

nonisolated struct AppAttestAssertionRequest: Encodable, Sendable {
    let keyId: String
    let challengeId: String
    let assertionObject: String
    let publicKey: String
}
