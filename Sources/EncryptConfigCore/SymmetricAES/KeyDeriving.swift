//
//  KeyDeriving.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra on 30/06/26.
//


import CryptoKit
import Foundation

public protocol KeyDeriving {
    func deriveKey(password: String, salt: Data) -> SymmetricKey
}