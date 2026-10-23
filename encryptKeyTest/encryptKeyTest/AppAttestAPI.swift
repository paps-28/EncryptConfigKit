import EncryptConfigRuntime
import Foundation
import OSLog

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
        AppAttestLog.flow.info("stage=device.keyId checking support")
        guard await manager.isSupported else {
            AppAttestLog.flow.error("stage=device.keyId App Attest is not supported")
            throw RemoteKeyProviderError.appAttestNotSupported
        }
        do {
            let exists = try await manager.currentKeyId() != nil
            AppAttestLog.flow.info("stage=device.keyId stored_key_present=\(exists)")
            let keyId = try await manager.getOrCreateKeyId()
            AppAttestLog.flow.info("stage=device.keyId ready")
            return keyId
        } catch {
            AppAttestLog.failure(error, stage: "device.keyId")
            throw error
        }
    }

    func attest(challenge: Data) async throws -> Data {
        AppAttestLog.flow.info("stage=apple.attestKey started")
        AppAttestLog.flow.debug("stage=apple.attestKey challenge_bytes=\(challenge.count)")
        do {
            let attestation = try await manager.generateAttestation(challenge: challenge)
            AppAttestLog.flow.info("stage=apple.attestKey succeeded")
            return attestation
        } catch {
            AppAttestLog.failure(error, stage: "apple.attestKey")
            throw error
        }
    }

    func assertion(challenge: Data, rsaPublicKey: Data) async throws -> Data {
        AppAttestLog.flow.info("stage=apple.generateAssertion started")
        AppAttestLog.flow.debug("stage=apple.generateAssertion challenge_bytes=\(challenge.count) rsa_der_bytes=\(rsaPublicKey.count)")
        do {
            let assertion = try await manager.generateAssertion(challenge: challenge, rsaPublicKey: rsaPublicKey)
            AppAttestLog.flow.info("stage=apple.generateAssertion succeeded")
            return assertion
        } catch {
            AppAttestLog.failure(error, stage: "apple.generateAssertion")
            throw error
        }
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
        AppAttestLog.flow.info("stage=flow started")
        var stage = "device.keyId"
        do {
            let keyId = try await provider.keyId()
            let challenge: AppAttestChallengeResponse
            stage = "assertion.challenge"
            do {
                challenge = try await requestChallenge(keyId: keyId, purpose: .assertion)
            } catch APIError.httpError(statusCode: 404) {
                AppAttestLog.flow.notice("stage=assertion.challenge key not registered; starting registration")
                stage = "registration"
                try await register(keyId: keyId)
                stage = "assertion.challenge"
                challenge = try await requestChallenge(keyId: keyId, purpose: .assertion)
            }
            stage = "assertion.decodeChallenge"
            let challengeData = try challenge.decodedChallenge()
            stage = "apple.generateAssertion"
            let assertion = try await provider.assertion(challenge: challengeData, rsaPublicKey: rsaPublicKey)
            stage = "aes.request"
            AppAttestLog.flow.info("stage=aes.request sending verified-key request")
            let response: EncryptedKeyResponseDTO = try await client.post(
                endpoint: "\(path)/public-key",
                body: AppAttestAssertionRequest(
                    keyId: keyId,
                    challengeId: challenge.challengeId,
                    assertionObject: assertion.base64EncodedString(),
                    publicKey: rsaPublicKey.base64EncodedString()
                )
            )
            AppAttestLog.flow.info("stage=aes.request encrypted response received")
            return response
        } catch {
            AppAttestLog.failure(error, stage: stage)
            throw error
        }
    }

    private func requestChallenge(keyId: String, purpose: AppAttestPurpose) async throws -> AppAttestChallengeResponse {
        AppAttestLog.flow.info("stage=challenge.request purpose=\(purpose.rawValue, privacy: .public)")
        let response: AppAttestChallengeResponse = try await client.post(
            endpoint: "\(path)/challenge",
            body: AppAttestChallengeRequest(keyId: keyId, purpose: purpose)
        )
        AppAttestLog.flow.info("stage=challenge.request received purpose=\(purpose.rawValue, privacy: .public)")
        return response
    }

    private func register(keyId: String) async throws {
        var stage = "registration.challenge"
        do {
            AppAttestLog.flow.info("stage=registration started")
            let challenge = try await requestChallenge(keyId: keyId, purpose: .attestation)
            stage = "registration.decodeChallenge"
            let challengeData = try challenge.decodedChallenge()
            stage = "apple.attestKey"
            let attestation = try await provider.attest(challenge: challengeData)
            stage = "registration.submit"
            AppAttestLog.flow.info("stage=registration.submit sending attestation to backend")
            try await client.post(
                endpoint: "\(path)/attest",
                body: AppAttestRegistrationRequest(
                    keyId: keyId,
                    challengeId: challenge.challengeId,
                    attestationObject: attestation.base64EncodedString()
                )
            )
            AppAttestLog.flow.info("stage=registration succeeded")
        } catch APIError.httpError(statusCode: 409) {
            // Another request may have completed registration, including after a lost response.
            // The assertion challenge and signature still have to pass server verification.
            AppAttestLog.flow.notice("stage=registration conflict; checking existing registration with an assertion")
            return
        } catch {
            AppAttestLog.failure(error, stage: stage)
            throw error
        }
    }
}
