import CryptoKit
import Foundation
import Security

protocol ECPrivateKeyStoring {
    func generate(tag: Data) throws
    func load(tag: Data) throws -> SecKey?
    func delete(tag: Data) throws
}

struct SecureEnclaveECKeyStore: ECPrivateKeyStoring {
    func generate(tag: Data) throws {
        guard SecureEnclave.isAvailable else {
            throw ECKeyManagerError.secureEnclaveUnavailable
        }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, &error
        ) else {
            if let error { throw error.takeRetainedValue() }
            throw ECKeyManagerError.accessControlCreationFailed
        }
        // Generation and persistence happen together; the private key is never exported.
        let attributes: [String: Any] = [
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: access
            ]
        ]
        guard SecKeyCreateRandomKey(attributes as CFDictionary, &error) != nil else {
            if let error { throw error.takeRetainedValue() }
            throw ECKeyManagerError.generationFailed
        }
    }

    func load(tag: Data) throws -> SecKey? {
        var query = keyQuery(tag: tag)
        query[kSecReturnRef as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let item,
              CFGetTypeID(item) == SecKeyGetTypeID() else {
            throw ECKeyManagerError.loadFailed(status == errSecSuccess ? errSecInternalComponent : status)
        }
        // The query and CF type check guarantee a SecKey reference.
        return (item as! SecKey)
    }

    func delete(tag: Data) throws {
        let status = SecItemDelete(keyQuery(tag: tag) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw ECKeyManagerError.deleteFailed(status)
        }
    }

    private func keyQuery(tag: Data) -> [String: Any] {
        [
            kSecUseDataProtectionKeychain as String: true,
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrApplicationTag as String: tag
        ]
    }
}
