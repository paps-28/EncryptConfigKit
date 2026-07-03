//
//  HKDFKeyDeriver.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra on 30/06/26.
//


import CryptoKit
import Foundation

public struct HKDFKeyDeriver: KeyDeriving {
    private let info: Data

    public init(info: String = "EncryptConfigKit.ConfigurationEncryption") {
        self.info = Data(info.utf8)
    }

    public func deriveKey(password: String, salt: Data) -> SymmetricKey {
        let passwordData = Data(password.utf8)
        let hash = SHA256.hash(data: passwordData)
        let inputKey = SymmetricKey(data: hash)

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKey,
            salt: salt,
            info: info,
            outputByteCount: 32
        )
    }
}