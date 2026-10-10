//
//  AppAttestKeyStore.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra Solis on 10/10/26.
//

import Foundation
import Security

public protocol AppAttestKeyStoring: Sendable {
    func loadKeyId() throws -> String?
    func saveKeyId(_ keyId: String) throws
    func deleteKeyId() throws
}

public struct AppAttestKeychainStore: AppAttestKeyStoring {
    
    private let service: String
    private let account: String
    
    public init(
        service: String,
        account: String
    ) {
        self.account = account
        self.service = service
    }
    
    public func loadKeyId() throws -> String? {
        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        
        var result: CFTypeRef?
        
        let status = SecItemCopyMatching(
            query as CFDictionary,
            &result
        )
        
        if status == errSecItemNotFound {
            return nil
        }
        
        guard status == errSecSuccess else {
            throw AppAttestError.keychainError(status)
        }
        
        guard let data = result as? Data,
              let keyId = String(
                data: data,
                encoding: .utf8
                ),
              !keyId.isEmpty else {
            throw AppAttestError.invalidKeyStoreId
        }
        
        return keyId
    }
    
    public func saveKeyId(_ keyId: String) throws {
        guard !keyId.isEmpty else {
            throw AppAttestError.invalidKeyStoreId
        }
        
        let data = Data(keyId.utf8)
        let query = baseQuery()
        
        let attributes: [String: Any] = [
            kSecValueData as String: data
        ]
        
        let updateStatus = SecItemUpdate(
            query as CFDictionary,
            attributes as CFDictionary
        )
        
        if updateStatus == errSecSuccess {
            return
        }
        
        guard updateStatus == errSecItemNotFound else {
            throw AppAttestError.keychainError(updateStatus)
        }
        
        var insert = query
        insert[kSecValueData as String] = data
        insert[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        
        let insertStatus = SecItemAdd(insert as CFDictionary, nil)
        
        guard insertStatus == errSecSuccess else {
            throw AppAttestError.keychainError(insertStatus)
        }
    }
    
    public func deleteKeyId() throws {
        let status = SecItemDelete(baseQuery() as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw AppAttestError.keychainError(status)
        }
    }
}

fileprivate extension AppAttestKeychainStore {
    func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
    }
}
