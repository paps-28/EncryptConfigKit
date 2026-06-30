//
//  TestKeyProvider.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra on 30/06/26.
//


import EncryptConfigCore
import EncryptConfigRuntime
import XCTest

private struct TestKeyProvider: ConfigurationKeyProvider {
    let password: String

    func configurationPassword() async throws -> String {
        password
    }
}

final class ConfigurationLoaderTests: XCTestCase {

    func testLoadDictionaryDecryptsEncryptedPlist() async throws {
        let password = "test-password"

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

        let encrypted = try EncryptionService().encrypt(
            data: plistData,
            password: password
        )

        let encryptedData = try JSONEncoder().encode(encrypted)

        let tempDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)

        try FileManager.default.createDirectory(
            at: tempDirectory,
            withIntermediateDirectories: true
        )

        let fileURL = tempDirectory.appendingPathComponent("SecretsConfig.plist.enc")

        try encryptedData.write(to: fileURL)

        let bundle = Bundle(path: tempDirectory.path)!

        let loader = ConfigurationLoader(
            keyProvider: TestKeyProvider(password: password),
            bundle: bundle,
            resourceName: "SecretsConfig",
            resourceExtension: "plist.enc"
        )

        let decoded = try await loader.loadDictionary()

        XCTAssertEqual(decoded["API_URL"] as? String, "https://api.example.com")
        XCTAssertEqual(decoded["CLIENT_ID"] as? String, "abc123")
        XCTAssertEqual(decoded["FEATURE_ENABLED"] as? Bool, true)
    }
}