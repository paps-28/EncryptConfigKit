//
//  RSAKeyManagerEncryptionTests.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra on 08/07/26.
//


import XCTest
import Security
@testable import EncryptConfigCore

final class RSAKeyManagerEncryptionTests: XCTestCase {

    func testEncryptWithPublicKeyAndDecryptWithPrivateKey() throws {
        let store = InMemoryPrivateKeyStore()

        let manager = RSAKeyManager(
            tag: "test.privatekey",
            keySize: 2048,
            generator: DefaultRSAKeyPairGenerator(),
            store: store,
            decryptor: DefaultRSADecryptor()
        )

        try manager.generateKeyPairIfNeeded()

        let plainData = Data("AES_KEY_TEST_123456789".utf8)

        let publicKey = try makePublicKey(
            fromBase64: try manager.publicKeyBase64()
        )

        let encryptedData = try encrypt(
            plainData,
            using: publicKey
        )

        let decryptedData = try manager.decrypt(
            encryptedData
        )

        XCTAssertEqual(
            decryptedData,
            plainData
        )
    }

    func testDecryptFailsWithDifferentPrivateKey() throws {
        let storeA = InMemoryPrivateKeyStore()
        let storeB = InMemoryPrivateKeyStore()

        let managerA = RSAKeyManager(
            tag: "test.privatekey.a",
            keySize: 2048,
            generator: DefaultRSAKeyPairGenerator(),
            store: storeA,
            decryptor: DefaultRSADecryptor()
        )

        let managerB = RSAKeyManager(
            tag: "test.privatekey.b",
            keySize: 2048,
            generator: DefaultRSAKeyPairGenerator(),
            store: storeB,
            decryptor: DefaultRSADecryptor()
        )

        try managerA.generateKeyPairIfNeeded()
        try managerB.generateKeyPairIfNeeded()

        let plainData = Data("AES_KEY_TEST_123456789".utf8)

        let publicKeyA = try makePublicKey(
            fromBase64: try managerA.publicKeyBase64()
        )

        let encryptedData = try encrypt(
            plainData,
            using: publicKeyA
        )

        XCTAssertThrowsError(
            try managerB.decrypt(encryptedData)
        )
    }
}

private extension RSAKeyManagerEncryptionTests {

    func makePublicKey(
        fromBase64 base64: String
    ) throws -> SecKey {

        guard let keyData = Data(base64Encoded: base64) else {
            throw TestRSAError.invalidBase64
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String:
                kSecAttrKeyTypeRSA,

            kSecAttrKeyClass as String:
                kSecAttrKeyClassPublic,

            kSecAttrKeySizeInBits as String:
                2048
        ]

        var error: Unmanaged<CFError>?

        guard let publicKey = SecKeyCreateWithData(
            keyData as CFData,
            attributes as CFDictionary,
            &error
        ) else {
            if let error {
                throw error.takeRetainedValue()
            }

            throw TestRSAError.publicKeyImportFailed
        }

        return publicKey
    }

    func encrypt(
        _ data: Data,
        using publicKey: SecKey
    ) throws -> Data {

        let algorithm: SecKeyAlgorithm = .rsaEncryptionOAEPSHA256

        guard SecKeyIsAlgorithmSupported(
            publicKey,
            .encrypt,
            algorithm
        ) else {
            throw TestRSAError.algorithmNotSupported
        }

        var error: Unmanaged<CFError>?

        guard let encryptedData = SecKeyCreateEncryptedData(
            publicKey,
            algorithm,
            data as CFData,
            &error
        ) as Data? else {
            if let error {
                throw error.takeRetainedValue()
            }

            throw TestRSAError.encryptionFailed
        }

        return encryptedData
    }
}

private enum TestRSAError: Error {
    case invalidBase64
    case publicKeyImportFailed
    case algorithmNotSupported
    case encryptionFailed
}
