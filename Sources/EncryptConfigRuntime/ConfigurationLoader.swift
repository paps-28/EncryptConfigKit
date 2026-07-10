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

    public init(
        keyProvider: ConfigurationKeyProvider,
        decryptionService: DecryptionService = DecryptionService()
    ) {
        self.keyProvider = keyProvider
        self.decryptionService = decryptionService
    }

    public func loadDictionary(
        fromEncryptedData encryptedData: Data
    ) async throws -> [String: Any] {

        let password = try await keyProvider.configurationPassword()

        let encryptedConfiguration = try JSONDecoder().decode(
            EncryptedConfiguration.self,
            from: encryptedData
        )

        let decryptedData = try decryptionService.decrypt(
            configuration: encryptedConfiguration,
            password: password
        )

        let object = try PropertyListSerialization.propertyList(
            from: decryptedData,
            options: [],
            format: nil
        )

        return object as? [String: Any] ?? [:]
    }

    public func loadDecodable<T: Decodable>(
        _ type: T.Type,
        from configuration: EncryptedConfiguration
    ) async throws -> T {

        let decryptedData = try await loadData(
            from: configuration
        )

        return try PropertyListDecoder().decode(
            T.self,
            from: decryptedData
        )
    }

    public func loadData(
        from configuration: EncryptedConfiguration
    ) async throws -> Data {

        let password = try await keyProvider.configurationPassword()

        return try decryptionService.decrypt(
            configuration: configuration,
            password: password
        )
    }
}
