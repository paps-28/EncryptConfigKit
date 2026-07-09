//
//  RSAKeyManager.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra on 03/07/26.
//

import Foundation
import Security

public final class RSAKeyManager: AsymmetricKeyManaging {

    private let tag: Data
    private let keySize: Int

    private let generator: RSAKeyPairGenerating
    private let store: PrivateKeyStoring
    private let decryptor: RSADecrypting

    // MARK: - Public

    public init(
        tag: String? = nil,
        keySize: Int = 3072
    ) {
        self.tag = Self.resolveTag(tag)
        self.keySize = keySize

        self.generator = DefaultRSAKeyPairGenerator()
        self.store = KeychainPrivateKeyStore()
        self.decryptor = DefaultRSADecryptor()
    }

    // MARK: - Internal / Testing

    init(
        tag: String? = nil,
        keySize: Int = 3072,
        generator: RSAKeyPairGenerating,
        store: PrivateKeyStoring,
        decryptor: RSADecrypting = DefaultRSADecryptor()
    ) {
        self.tag = Self.resolveTag(tag)
        self.keySize = keySize

        self.generator = generator
        self.store = store
        self.decryptor = decryptor
    }

    public func generateKeyPairIfNeeded() throws {
        guard !hasPrivateKey() else {
            return
        }

        let privateKey = try generator.generatePrivateKey(
            keySize: keySize
        )

        try store.save(
            privateKey,
            tag: tag
        )
    }

    public func publicKeyBase64() throws -> String {
        let privateKey = try loadPrivateKey()

        let publicKey = try generator.getPublicKey(
            from: privateKey
        )

        let publicKeyData = try generator.externalRepresentation(
            of: publicKey
        )

        return publicKeyData.base64EncodedString()
    }

    public func publicKeyPEM() throws -> String {
        let base64 = try publicKeyBase64()

        let formatted = base64
            .chunked(into: 64)
            .joined(separator: "\n")

        return """
        -----BEGIN RSA PUBLIC KEY-----
        \(formatted)
        -----END RSA PUBLIC KEY-----
        """
    }

    public func decrypt(
        _ data: Data
    ) throws -> Data {

        let privateKey = try loadPrivateKey()

        return try decryptor.decrypt(
            data,
            using: privateKey
        )
    }

    public func hasPrivateKey() -> Bool {
        do {
            return try store.load(
                tag: tag
            ) != nil
        } catch {
            return false
        }
    }

    public func deleteKeyPair() throws {
        try store.delete(
            tag: tag
        )
    }
}

private extension RSAKeyManager {

    static func resolveTag(
        _ customTag: String?
    ) -> Data {

        let bundleId =
            Bundle.main.bundleIdentifier
            ?? "default.app"

        let resolvedTag =
            customTag
            ?? "\(bundleId).crypto.privatekey"

        return Data(resolvedTag.utf8)
    }

    func loadPrivateKey() throws -> SecKey {
        guard let privateKey = try store.load(
            tag: tag
        ) else {
            throw RSAKeyManagerError.privateKeyNotFound
        }

        return privateKey
    }
}

private extension String {
    func chunked(into size: Int) -> [String] {
        stride(from: 0, to: count, by: size).map {
            let start = index(startIndex, offsetBy: $0)
            let end = index(start, offsetBy: size, limitedBy: endIndex) ?? endIndex
            return String(self[start..<end])
        }
    }
}
