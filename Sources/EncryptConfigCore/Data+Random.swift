//
//  Data+Random.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra on 30/06/26.
//

import Foundation
import Security

extension Data {
    static func secureRandom(count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)

        let status = SecRandomCopyBytes(
            kSecRandomDefault,
            count,
            &bytes
        )

        guard status == errSecSuccess else {
            throw CryptoConfigurationError.randomGenerationFailed
        }

        return Data(bytes)
    }
}
