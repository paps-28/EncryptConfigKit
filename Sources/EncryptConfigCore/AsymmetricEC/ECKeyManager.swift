import CryptoKit
import Foundation
import Security

/// Persistent P-256 keys generated exclusively in Secure Enclave.
/// Uses Apple's ECIES cofactor X9.63 SHA-256 / AES-GCM ciphertext format.
/// RSA ciphertext and arbitrary ECDH/AES envelopes are not compatible.
public final class ECKeyManager: AsymmetricKeyManaging {
    private let tag: Data
    private let store: ECPrivateKeyStoring

    public init(tag: String? = nil) {
        self.tag = Self.resolveTag(tag)
        self.store = SecureEnclaveECKeyStore()
    }

    init(tag: String, store: ECPrivateKeyStoring) {
        self.tag = Self.resolveTag(tag)
        self.store = store
    }

    /// Throws on unsupported hardware; never falls back to software.
    public func generateKeyPairIfNeeded() throws {
        guard try store.load(tag: tag) == nil else { return }
        try store.generate(tag: tag)
    }

    /// Returns an X.509 SubjectPublicKeyInfo DER encoded as Base64.
    public func publicKeyBase64() throws -> String {
        try publicKeyRepresentation().derRepresentation.base64EncodedString()
    }

    public func publicKeyPEM() throws -> String {
        try publicKeyRepresentation().pemRepresentation
    }

    public func decrypt(_ data: Data) throws -> Data {
        let privateKey = try loadPrivateKey()
        let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorX963SHA256AESGCM
        guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, algorithm) else {
            throw ECKeyManagerError.algorithmNotSupported
        }
        var error: Unmanaged<CFError>?
        guard let result = SecKeyCreateDecryptedData(
            privateKey, algorithm, data as CFData, &error
        ) as Data? else {
            if let error { throw error.takeRetainedValue() }
            throw ECKeyManagerError.decryptionFailed
        }
        return result
    }

    /// Returns false for both a missing key and a Keychain access error.
    /// Use the throwing operations when the distinction matters.
    public func hasPrivateKey() -> Bool {
        (try? store.load(tag: tag)) != nil
    }

    public func deleteKeyPair() throws {
        try store.delete(tag: tag)
    }

    private func loadPrivateKey() throws -> SecKey {
        guard let key = try store.load(tag: tag) else {
            throw ECKeyManagerError.privateKeyNotFound
        }
        return key
    }

    private func publicKeyRepresentation() throws -> P256.KeyAgreement.PublicKey {
        guard let publicKey = SecKeyCopyPublicKey(try loadPrivateKey()) else {
            throw ECKeyManagerError.publicKeyNotFound
        }
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            if let error { throw error.takeRetainedValue() }
            throw ECKeyManagerError.publicKeyExportFailed
        }
        return try P256.KeyAgreement.PublicKey(x963Representation: data)
    }

    private static func resolveTag(_ customTag: String?) -> Data {
        let bundleID = Bundle.main.bundleIdentifier ?? "default.app"
        return Data((customTag ?? "\(bundleID).crypto.ec.privatekey").utf8)
    }
}
