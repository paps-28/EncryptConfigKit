//
//  EncryptionService.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra on 30/06/26.
//


import CryptoKit
import Foundation

public struct EncryptionService {
    private let keyDeriver: KeyDeriving

    public init(keyDeriver: KeyDeriving = HKDFKeyDeriver()) {
        self.keyDeriver = keyDeriver
    }

    public func encrypt(
        data: Data,
        password: String
    ) throws -> EncryptedConfiguration {
        let salt = try Data.secureRandom(count: 16)

        let key = keyDeriver.deriveKey(
            password: password,
            salt: salt
        )

        let sealedBox = try AES.GCM.seal(
            data,
            using: key
        )

        guard let combined = sealedBox.combined else {
            throw CryptoConfigurationError.invalidCombinedRepresentation
        }

        return EncryptedConfiguration(
            salt: salt,
            combined: combined
        )
    }
}