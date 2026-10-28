//
//  RemoteKeyProvider.swift
//  encryptKeyTest
//

import EncryptConfigCore
import EncryptConfigRuntime
import Foundation
import OSLog

@MainActor
final class RemoteKeyProvider: ConfigurationKeyProvider {
    static let shared = RemoteKeyProvider()

    private let api: AppAttestAPI
    private let rsaProvider = RSAKeyManager(algorithm: .rsaEncryptionOAEPSHA512)
    private var pendingTask: Task<String, Error>?

    init(client: APIClient? = nil, attestProvider: (any AppAttestProviding)? = nil) {
        let client = client ?? APIClient()
        api = AppAttestAPI(
            client: client,
            provider: attestProvider ?? DeviceAppAttestProvider(baseURL: client.baseURL)
        )
    }

    func configurationPassword() async throws -> String {
        // Coalesce concurrent loads so assertions for the same key cannot arrive out of order.
        if let pendingTask {
            AppAttestLog.flow.debug("stage=aes.load joining in-flight request")
            return try await pendingTask.value
        }
        let task = Task {
            do {
                return try await fetchPassword()
            } catch {
                AppAttestLog.failure(error, stage: "aes.load")
                throw error
            }
        }
        pendingTask = task
        defer { pendingTask = nil }
        return try await task.value
    }

    private func fetchPassword() async throws -> String {
        AppAttestLog.flow.info("stage=rsa.prepare started")
        try rsaProvider.generateKeyPairIfNeeded()
        let publicKeyBase64 = try rsaProvider.publicKeyBase64()
        guard let publicKeyDER = Data(base64Encoded: publicKeyBase64), !publicKeyDER.isEmpty else {
            throw RemoteKeyProviderError.invalidPublicKey
        }
        AppAttestLog.flow.info("stage=rsa.prepare ready")
        AppAttestLog.flow.debug("stage=rsa.prepare public_key_der_bytes=\(publicKeyDER.count)")
        let response = try await api.encryptedKey(rsaPublicKey: publicKeyDER)
        AppAttestLog.flow.info("stage=aes.decodeResponse started")
        guard let encryptedData = Data(base64Encoded: response.encryptedKey), !encryptedData.isEmpty else {
            throw RemoteKeyProviderError.noEncryptedKey
        }
        AppAttestLog.flow.info("stage=aes.decrypt started")
        let decrypted: Data
        do {
            decrypted = try rsaProvider.decrypt(encryptedData)
        } catch {
            AppAttestLog.failure(error, stage: "aes.decrypt")
            throw error
        }
        guard let password = String(data: decrypted, encoding: .utf8), !password.isEmpty else {
            throw RemoteKeyProviderError.invalidDecryption
        }
        AppAttestLog.flow.info("stage=aes.decrypt succeeded; configuration password is ready")
        return password
    }
}

enum RemoteKeyProviderError: LocalizedError {
    case appAttestNotSupported
    case invalidChallenge
    case invalidPublicKey
    case noEncryptedKey
    case invalidDecryption

    var errorDescription: String? {
        switch self {
        case .appAttestNotSupported:
            return "App Attest no está disponible. Ejecuta la app firmada en un iPhone/iPad físico compatible."
        case .invalidChallenge:
            return "El servidor devolvió un challenge de App Attest inválido."
        case .invalidPublicKey:
            return "No se pudo exportar la clave pública RSA."
        case .noEncryptedKey:
            return "El servidor no devolvió una clave cifrada válida."
        case .invalidDecryption:
            return "No se pudo descifrar la clave de configuración."
        }
    }
}
