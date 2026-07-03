//
//  DecryptionService.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra on 30/06/26.
//


import CryptoKit
import Foundation

public struct DecryptionService {
    private let keyDeriver: KeyDeriving

    public init(keyDeriver: KeyDeriving = HKDFKeyDeriver()) {
        self.keyDeriver = keyDeriver
    }

    public func decrypt(
        configuration: EncryptedConfiguration,
        password: String
    ) throws -> Data {
        let key = keyDeriver.deriveKey(
            password: password,
            salt: configuration.salt
        )

        let sealedBox = try AES.GCM.SealedBox(
            combined: configuration.combined
        )

        return try AES.GCM.open(
            sealedBox,
            using: key
        )
    }
}