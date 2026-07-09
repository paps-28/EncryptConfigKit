//
//  KeychainRSAKeyManagerTests.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra on 03/07/26.
//


import XCTest
@testable import EncryptConfigCore

final class InMemoryPrivateKeyStore: PrivateKeyStoring {

    var storage: [Data: SecKey] = [:]

    func save(_ key: SecKey, tag: Data) throws {
        storage[tag] = key
    }

    func load(tag: Data) throws -> SecKey? {
        storage[tag]
    }

    func delete(tag: Data) throws {
        storage.removeValue(forKey: tag)
    }
}

final class RSAKeyManagerTests: XCTestCase {
    
    func testGenerateKeyPairCreatesPrivateKey() throws {
        let store = InMemoryPrivateKeyStore()
        
        let manager = RSAKeyManager(
            tag: "test.privatekey",
            keySize: 2048,
            generator: DefaultRSAKeyPairGenerator(),
            store: InMemoryPrivateKeyStore(),
            decryptor: DefaultRSADecryptor()
        )
        
        XCTAssertFalse(manager.hasPrivateKey())
        
        try manager.generateKeyPairIfNeeded()
        
        XCTAssertTrue(manager.hasPrivateKey())
    }
    
    func testPublicKeyPEMReturnsValidFormat() throws {
        let store = InMemoryPrivateKeyStore()
        
        let manager = RSAKeyManager(
            tag: "test.privatekey",
            keySize: 2048,
            generator: DefaultRSAKeyPairGenerator(),
            store: InMemoryPrivateKeyStore(),
            decryptor: DefaultRSADecryptor()
        )
        
        try manager.generateKeyPairIfNeeded()
        
        let pem = try manager.publicKeyPEM()
        
        XCTAssertTrue(pem.contains("-----BEGIN RSA PUBLIC KEY-----"))
        XCTAssertTrue(pem.contains("-----END RSA PUBLIC KEY-----"))
    }
    
    func testDeleteKeyPairRemovesPrivateKey() throws {
        let manager = RSAKeyManager(
            tag: "test.privatekey",
            keySize: 2048,
            generator: DefaultRSAKeyPairGenerator(),
            store: InMemoryPrivateKeyStore(),
            decryptor: DefaultRSADecryptor()
        )
        
        try manager.generateKeyPairIfNeeded()
        XCTAssertTrue(manager.hasPrivateKey())
        
        try manager.deleteKeyPair()
        XCTAssertFalse(manager.hasPrivateKey())
    }
}
