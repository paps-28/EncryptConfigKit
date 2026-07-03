//
//  AsymmetricKeyManaging.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra on 03/07/26.
//

import Foundation
import Security

public protocol AsymmetricKeyManaging {
    func generateKeyPairIfNeeded() throws
    func publicKeyBase64() throws -> String
    func publicKeyPEM() throws -> String
    func hasPrivateKey() -> Bool
    func deleteKeyPair() throws
}

public protocol RSAKeyPairGenerating {
    func generatePrivateKey(keySize: Int) throws -> SecKey
    func getPublicKey(from privateKey: SecKey) throws -> SecKey
    func externalRepresentation(of key: SecKey) throws -> Data
}

public protocol PrivateKeyStoring {
    func save(_ key: SecKey, tag: Data) throws
    func load(tag: Data) throws -> SecKey?
    func delete(tag: Data) throws
}
