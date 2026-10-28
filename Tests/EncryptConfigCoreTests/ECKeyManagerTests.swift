import CryptoKit
import Foundation
import Security
import Testing
@testable import EncryptConfigCore

struct ECKeyManagerTests {
    @Test func publicKeyExportAndDecryption() throws {
        let store = MemoryECStore()
        let manager = ECKeyManager(tag: "test.ec", store: store)
        try manager.generateKeyPairIfNeeded()
        let original = try manager.publicKeyBase64()
        try manager.generateKeyPairIfNeeded()
        #expect(try manager.publicKeyBase64() == original)
        #expect(store.generations == 1)

        let publicKey = try P256.KeyAgreement.PublicKey(pemRepresentation: manager.publicKeyPEM())
        #expect(publicKey.derRepresentation.base64EncodedString() == original)
        let ciphertext = try encrypt(Data("secret".utf8), publicKey: publicKey)
        #expect(try manager.decrypt(ciphertext) == Data("secret".utf8))
        var tampered = ciphertext
        tampered[tampered.count - 1] ^= 1
        #expect(throws: (any Error).self) { try manager.decrypt(tampered) }

        let other = ECKeyManager(tag: "other", store: MemoryECStore())
        try other.generateKeyPairIfNeeded()
        #expect(throws: (any Error).self) { try other.decrypt(ciphertext) }
        try manager.deleteKeyPair()
        #expect(!manager.hasPrivateKey())
        #expect(throws: (any Error).self) { try manager.decrypt(ciphertext) }
    }

    @Test func loadFailureDoesNotGenerateReplacement() throws {
        let store = MemoryECStore()
        store.failLoad = true
        let manager = ECKeyManager(tag: "test.ec", store: store)
        #expect(throws: (any Error).self) { try manager.generateKeyPairIfNeeded() }
        #expect(store.generations == 0)
    }

    @Test(.enabled(if: !SecureEnclave.isAvailable))
    func unsupportedHardwareFailsExplicitly() {
        #expect(throws: (any Error).self) {
            try ECKeyManager(tag: "test.ec.\(UUID().uuidString)").generateKeyPairIfNeeded()
        }
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

private final class MemoryECStore: ECPrivateKeyStoring {
    var key: SecKey?
    var generations = 0
    var failLoad = false

    func generate(tag: Data) throws {
        generations += 1
        key = try #require(SecKeyCreateRandomKey([
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256
        ] as CFDictionary, nil))
    }

    func load(tag: Data) throws -> SecKey? {
        if failLoad { throw ECKeyManagerError.loadFailed(errSecInteractionNotAllowed) }
        return key
    }

    func delete(tag: Data) throws { key = nil }
}
