import CryptoKit
import Foundation
import Security
import Testing
@testable import EncryptConfigCore

// These tests require the signed app host; the Swift package runner has no Keychain identity.
struct KeyPersistenceIntegrationTests {
    @Test(.enabled(if: SecureEnclave.isAvailable))
    func secureEnclavePersistenceAndDecryption() throws {
        let tag = "test.ec.\(UUID().uuidString)"
        let manager = ECKeyManager(tag: tag)
        defer { try? manager.deleteKeyPair() }
        try manager.generateKeyPairIfNeeded()
        let publicKey = try P256.KeyAgreement.PublicKey(pemRepresentation: manager.publicKeyPEM())
        let ciphertext = try encrypt(Data("hardware secret".utf8), publicKey: publicKey)
        let reloaded = ECKeyManager(tag: tag)
        #expect(try reloaded.decrypt(ciphertext) == Data("hardware secret".utf8))
        let key = try #require(try SecureEnclaveECKeyStore().load(tag: Data(tag.utf8)))
        var error: Unmanaged<CFError>?
        #expect(SecKeyCopyExternalRepresentation(key, &error) == nil)
        _ = error?.takeRetainedValue()
        try reloaded.deleteKeyPair()
        #expect(!manager.hasPrivateKey())
    }

    @Test func persistedKeyDecryptsAndDuplicateSavePreservesKey() throws {
        let tag = Data("test.rsa.\(UUID().uuidString)".utf8)
        let store = KeychainPrivateKeyStore()
        defer { try? store.delete(tag: tag) }
        let generator = DefaultRSAKeyPairGenerator()
        let key = try generator.generatePrivateKey(keySize: 2048)
        try store.save(key, tag: tag)
        let other = try generator.generatePrivateKey(keySize: 2048)
        #expect(throws: (any Error).self) { try store.save(other, tag: tag) }
        let publicKey = try generator.getPublicKey(from: key)
        let plaintext = Data("persisted secret".utf8)
        let encrypted = try #require(SecKeyCreateEncryptedData(
            publicKey, .rsaEncryptionOAEPSHA256, plaintext as CFData, nil
        ) as Data?)
        let reloaded = try #require(try store.load(tag: tag))
        #expect(try DefaultRSADecryptor().decrypt(encrypted, using: reloaded) == plaintext)
    }

    private func encrypt(_ data: Data, publicKey: P256.KeyAgreement.PublicKey) throws -> Data {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic
        ]
        let key = try #require(SecKeyCreateWithData(
            publicKey.x963Representation as CFData, attributes as CFDictionary, nil
        ))
        return try #require(SecKeyCreateEncryptedData(
            key, .eciesEncryptionCofactorX963SHA256AESGCM, data as CFData, nil
        ) as Data?)
    }
}
