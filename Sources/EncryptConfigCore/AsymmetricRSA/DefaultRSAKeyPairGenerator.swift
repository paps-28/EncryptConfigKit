//
//  DefaultRSAKeyPairGenerator.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra on 03/07/26.
//

import Foundation

final class DefaultRSAKeyPairGenerator: RSAKeyPairGenerating {

    init() {}

    func generatePrivateKey(keySize: Int) throws -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: keySize
        ]

        var error: Unmanaged<CFError>?

        guard let privateKey = SecKeyCreateRandomKey(
            attributes as CFDictionary,
            &error
        ) else {
            throw RSAKeyManagerError.generationFailed
        }

        return privateKey
    }

    func getPublicKey(from privateKey: SecKey) throws -> SecKey {
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw RSAKeyManagerError.publicKeyNotFound
        }

        return publicKey
    }

    func externalRepresentation(of key: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?

        guard let data = SecKeyCopyExternalRepresentation(
            key,
            &error
        ) as Data? else {
            throw RSAKeyManagerError.publicKeyExportFailed
        }

        return data
    }
}
