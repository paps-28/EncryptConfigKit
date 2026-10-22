import EncryptConfigRuntime
import Foundation

@MainActor
protocol AppAttestProviding {
    func keyId() async throws -> String
    func attest(challenge: Data) async throws -> Data
    func assertion(challenge: Data, rsaPublicKey: Data) async throws -> Data
}

@MainActor
struct DeviceAppAttestProvider: AppAttestProviding {
    private let manager: AppAttestManager

    init(baseURL: URL?) {
        let bundleId = Bundle.main.bundleIdentifier ?? "com.encryptKeyTest"
        let environment = Bundle.main.object(forInfoDictionaryKey: "AppAttestEnvironment") as? String ?? "unconfigured"
        // A development key must never be reused against a different backend or environment.
        let store = AppAttestKeychainStore(
            service: "\(bundleId).AppAttest.\(environment).\(baseURL?.absoluteString ?? "unconfigured")",
            account: "keyId"
        )
        manager = AppAttestManager(keyStore: store)
    }

    func keyId() async throws -> String {
        guard await manager.isSupported else {
            throw RemoteKeyProviderError.appAttestNotSupported
        }
        return try await manager.getOrCreateKeyId()
    }

    func attest(challenge: Data) async throws -> Data {
        try await manager.generateAttestation(challenge: challenge)
    }

    func assertion(challenge: Data, rsaPublicKey: Data) async throws -> Data {
        try await manager.generateAssertion(challenge: challenge, rsaPublicKey: rsaPublicKey)
    }
}

@MainActor
final class AppAttestAPI {
    private let client: APIClient
    private let provider: any AppAttestProviding
    private let path = "/api/crypto/app-attest"

    init(client: APIClient, provider: any AppAttestProviding) {
        self.client = client
        self.provider = provider
    }

    func encryptedKey(rsaPublicKey: Data) async throws -> EncryptedKeyResponseDTO {
        let keyId = try await provider.keyId()
        let challenge: AppAttestChallengeResponse
        do {
            challenge = try await requestChallenge(keyId: keyId, purpose: .assertion)
        } catch APIError.httpError(statusCode: 404) {
            try await register(keyId: keyId)
            challenge = try await requestChallenge(keyId: keyId, purpose: .assertion)
        }
        let assertion = try await provider.assertion(
            challenge: challenge.decodedChallenge(),
            rsaPublicKey: rsaPublicKey
        )
        return try await client.post(
            endpoint: "\(path)/public-key",
            body: AppAttestAssertionRequest(
                keyId: keyId,
                challengeId: challenge.challengeId,
                assertionObject: assertion.base64EncodedString(),
                // Same PEM transport as CryptoController; the assertion still hashes raw DER.
                publicKey: "-----BEGIN PUBLIC KEY-----\n\(rsaPublicKey.base64EncodedString())\n-----END PUBLIC KEY-----"
            )
        )
    }

    private func requestChallenge(keyId: String, purpose: AppAttestPurpose) async throws -> AppAttestChallengeResponse {
        try await client.post(
            endpoint: "\(path)/challenge",
            body: AppAttestChallengeRequest(keyId: keyId, purpose: purpose)
        )
    }

    private func register(keyId: String) async throws {
        do {
            let challenge = try await requestChallenge(keyId: keyId, purpose: .attestation)
            let attestation = try await provider.attest(challenge: challenge.decodedChallenge())
            try await client.post(
                endpoint: "\(path)/attest",
                body: AppAttestRegistrationRequest(
                    keyId: keyId,
                    challengeId: challenge.challengeId,
                    attestationObject: attestation.base64EncodedString()
                )
            )
        } catch APIError.httpError(statusCode: 409) {
            // Another request may have completed registration, including after a lost response.
            // The assertion challenge and signature still have to pass server verification.
            return
        }
    }
}
