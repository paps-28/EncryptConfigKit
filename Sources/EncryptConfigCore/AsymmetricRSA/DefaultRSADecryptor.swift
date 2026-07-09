//
//  DefaultRSADecryptor.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra on 08/07/26.
//

import Foundation
import Security

final class DefaultRSADecryptor: RSADecrypting {

    private let algorithm: SecKeyAlgorithm

    init(
        algorithm: SecKeyAlgorithm = .rsaEncryptionOAEPSHA256
    ) {
        self.algorithm = algorithm
    }

    func decrypt(
        _ data: Data,
        using privateKey: SecKey
    ) throws -> Data {

        guard SecKeyIsAlgorithmSupported(
            privateKey,
            .decrypt,
            algorithm
        ) else {
            throw RSAKeyManagerError.algorithmNotSupported
        }

        var error: Unmanaged<CFError>?

        guard let decryptedData =
                SecKeyCreateDecryptedData(
                    privateKey,
                    algorithm,
                    data as CFData,
                    &error
                ) as Data? else {

            if let error {
                throw error.takeRetainedValue()
            }

            throw RSAKeyManagerError.decryptionFailed
        }

        return decryptedData
    }
}
