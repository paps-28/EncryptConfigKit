//
//  ConfigurationLoader.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra on 30/06/26.
//


import EncryptConfigCore
import Foundation

public final class ConfigurationLoader {
    private let keyProvider: ConfigurationKeyProvider
    private let decryptionService: DecryptionService
    private let bundle: Bundle
    private let resourceName: String
    private let resourceExtension: String

    public init(
        keyProvider: ConfigurationKeyProvider,
        bundle: Bundle = .main,
        resourceName: String = "SecretsConfig",
        resourceExtension: String = "plist.enc",
        decryptionService: DecryptionService = DecryptionService()
    ) {
        self.keyProvider = keyProvider
        self.bundle = bundle
        self.resourceName = resourceName
        self.resourceExtension = resourceExtension
        self.decryptionService = decryptionService
    }

    public func loadDictionary() async throws -> [String: Any] {
        let data = try await loadData()

        let object = try PropertyListSerialization.propertyList(
            from: data,
            options: [],
            format: nil
        )

        return object as? [String: Any] ?? [:]
    }

    public func loadData() async throws -> Data {
        let password = try await keyProvider.configurationPassword()

        guard let url = bundle.url(
            forResource: resourceName,
            withExtension: resourceExtension
        ) else {
            throw CocoaError(.fileNoSuchFile)
        }

        let encryptedData = try Data(contentsOf: url)

        let encryptedConfiguration = try JSONDecoder().decode(
            EncryptedConfiguration.self,
            from: encryptedData
        )

        return try decryptionService.decrypt(
            configuration: encryptedConfiguration,
            password: password
        )
    }
}