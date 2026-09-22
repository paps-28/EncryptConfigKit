//
//  KeyProvider.swift
//  encryptKeyTest
//
//  Created by Pedro Alberto Parra on 02/07/26.
//

import EncryptConfigCore
import EncryptConfigRuntime

struct LocalKeyProvider: ConfigurationKeyProvider {

    func configurationPassword() async throws -> String {
        "eosqFMaSmizdHNGVuYsaGDFpJ2uCB2EGc7RGBm7IKfE="
    }

}
