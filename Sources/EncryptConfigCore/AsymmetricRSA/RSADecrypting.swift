//
//  RSADecrypting.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra on 08/07/26.
//

import Foundation

protocol RSADecrypting {
    func decrypt(
        _ data: Data,
        using privateKey: SecKey
    ) throws -> Data
}
