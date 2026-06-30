//
//  EncryptionServiceTests.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra on 30/06/26.
//


import XCTest
@testable import EncryptConfigCore

final class EncryptionServiceTests: XCTestCase {

    func testEncryptAndDecryptReturnsOriginalData() throws {
        let originalData = Data("Hola mundo".utf8)
        let password = "test-password-123"

        let encrypted = try EncryptionService().encrypt(
            data: originalData,
            password: password
        )

        let decrypted = try DecryptionService().decrypt(
            configuration: encrypted,
            password: password
        )

        XCTAssertEqual(decrypted, originalData)
    }

    func testEncryptGeneratesDifferentOutputForSameInput() throws {
        let originalData = Data("Hola mundo".utf8)
        let password = "test-password-123"

        let first = try EncryptionService().encrypt(
            data: originalData,
            password: password
        )

        let second = try EncryptionService().encrypt(
            data: originalData,
            password: password
        )

        XCTAssertNotEqual(first.salt, second.salt)
        XCTAssertNotEqual(first.combined, second.combined)
    }

    func testDecryptWithWrongPasswordFails() throws {
        let originalData = Data("Hola mundo".utf8)

        let encrypted = try EncryptionService().encrypt(
            data: originalData,
            password: "correct-password"
        )

        XCTAssertThrowsError(
            try DecryptionService().decrypt(
                configuration: encrypted,
                password: "wrong-password"
            )
        )
    }

    func testEncryptedConfigurationCanBeEncodedAndDecoded() throws {
        let originalData = Data("Hola mundo".utf8)
        let password = "test-password-123"

        let encrypted = try EncryptionService().encrypt(
            data: originalData,
            password: password
        )

        let encoded = try JSONEncoder().encode(encrypted)

        let decoded = try JSONDecoder().decode(
            EncryptedConfiguration.self,
            from: encoded
        )

        let decrypted = try DecryptionService().decrypt(
            configuration: decoded,
            password: password
        )

        XCTAssertEqual(decrypted, originalData)
    }

    func testCanEncryptAndDecryptPlistData() throws {
        let plist: [String: Any] = [
            "API_URL": "https://api.example.com",
            "CLIENT_ID": "abc123",
            "FEATURE_ENABLED": true
        ]

        let plistData = try PropertyListSerialization.data(
            fromPropertyList: plist,
            format: .xml,
            options: 0
        )

        let password = "test-password-123"

        let encrypted = try EncryptionService().encrypt(
            data: plistData,
            password: password
        )

        let decryptedData = try DecryptionService().decrypt(
            configuration: encrypted,
            password: password
        )

        let object = try PropertyListSerialization.propertyList(
            from: decryptedData,
            options: [],
            format: nil
        )

        let decodedPlist = object as? [String: Any]

        XCTAssertEqual(decodedPlist?["API_URL"] as? String, "https://api.example.com")
        XCTAssertEqual(decodedPlist?["CLIENT_ID"] as? String, "abc123")
        XCTAssertEqual(decodedPlist?["FEATURE_ENABLED"] as? Bool, true)
    }
}