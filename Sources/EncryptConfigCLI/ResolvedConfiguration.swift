//
//  ResolvedConfiguration.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra on 10/07/26.
//

import Foundation

struct ResolvedConfiguration {
    let environment: String
    let input: String
    let keyId: String?
    let keyEnvironmentVariable: String
}

func resolveConfiguration(
    arguments: Arguments,
    processEnvironment: [String: String]
) throws -> ResolvedConfiguration {

    if let configPath = arguments.config {
        return try resolveFromConfigurationFile(
            configPath: configPath,
            requestedEnvironment: arguments.environment,
            processEnvironment: processEnvironment
        )
    }

    guard
        let input = arguments.input,
        let keyEnvironment = arguments.keyEnvironment
    else {
        throw CLIError.missingRequiredArguments
    }

    return ResolvedConfiguration(
        environment: arguments.environment ?? "legacy",
        input: input,
        keyId: nil,
        keyEnvironmentVariable: keyEnvironment
    )
}

private func resolveFromConfigurationFile(
    configPath: String,
    requestedEnvironment: String?,
    processEnvironment: [String: String]
) throws -> ResolvedConfiguration {

    let configURL = URL(
        fileURLWithPath: configPath
    )

    let configData = try Data(
        contentsOf: configURL
    )

    let config: EncryptConfigFile

    do {
        config = try JSONDecoder().decode(
            EncryptConfigFile.self,
            from: configData
        )
    } catch {
        throw CLIError.invalidConfigurationFile(
            error.localizedDescription
        )
    }

    let environment =
        requestedEnvironment
        ?? processEnvironment["CONFIG_ENV"]
        ?? config.defaultEnvironment

    guard let environmentConfig =
        config.environments[environment]
    else {
        throw CLIError.environmentNotFound(
            environment
        )
    }

    let configDirectory =
        configURL.deletingLastPathComponent()

    let inputURL = resolveURL(
        path: environmentConfig.input,
        relativeTo: configDirectory
    )

    return ResolvedConfiguration(
        environment: environment,
        input: inputURL.path,
        keyId: environmentConfig.keyId,
        keyEnvironmentVariable:
            environmentConfig.keyEnvironmentVariable
    )
}

private func resolveURL(
    path: String,
    relativeTo baseURL: URL
) -> URL {
    if path.hasPrefix("/") {
        return URL(
            fileURLWithPath: path
        )
    }

    return baseURL
        .appendingPathComponent(path)
        .standardizedFileURL
}
