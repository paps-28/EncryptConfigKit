//
//  KeychainPrivateKeyStore.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra on 03/07/26.
//

import Foundation
import Security

final class KeychainPrivateKeyStore: PrivateKeyStoring {

    init() {}

    func save(_ key: SecKey, tag: Data) throws {
        // Do not replace an existing key: previously encrypted data still needs it.
        // Keychain's primary key also includes the public-key hash, so a matching
        // application tag alone does not make SecItemAdd reject a different key.
        guard try load(tag: tag) == nil else {
            throw RSAKeyManagerError.saveFailed(errSecDuplicateItem)
        }
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecValueRef as String: key,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]

        let status = SecItemAdd(query as CFDictionary, nil)

        guard status == errSecSuccess else {
            throw RSAKeyManagerError.saveFailed(status)
        }
    }

    func load(tag: Data) throws -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecReturnRef as String: true
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        if status == errSecItemNotFound {
            return nil
        }

        guard status == errSecSuccess else {
            throw RSAKeyManagerError.loadFailed(status)
        }

        guard let item, CFGetTypeID(item) == SecKeyGetTypeID() else {
            throw RSAKeyManagerError.loadFailed(errSecInternalComponent)
        }
        return (item as! SecKey)
    }

    func delete(tag: Data) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA
        ]

        let status = SecItemDelete(query as CFDictionary)

        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw RSAKeyManagerError.deleteFailed(status)
        }
    }
}
