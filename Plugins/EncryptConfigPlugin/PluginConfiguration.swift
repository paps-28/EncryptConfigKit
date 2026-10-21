//
//  PluginConfiguration.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra on 02/07/26.
//


import PackagePlugin
import Foundation

private struct PluginConfiguration: Decodable {
    let defaultEnvironment: String
    let symbol: String?
    let environments: [String: EnvironmentConfiguration]
}

private struct EnvironmentConfiguration: Decodable {
    let input: String
    let keyId: String?
    let keyEnvironmentVariable: String
}

private enum PluginConfigurationError: LocalizedError {
    case environmentNotFound(String)
    case missingKeyEnvironmentVariable(String)

    var errorDescription: String? {
        switch self {
        case .environmentNotFound(let environment):
            return """
            Environment '\(environment)' was not found in encrypt-config.json.
            """

        case .missingKeyEnvironmentVariable(let variable):
            return """
            Environment variable '\(variable)' is missing or empty.
            """
        }
    }
}

@main
struct EncryptConfigPlugin: BuildToolPlugin {

    func createBuildCommands(
        context: PluginContext,
        target: Target
    ) throws -> [Command] {

        guard let target = target as? SourceModuleTarget else {
            return []
        }
        
        let tool = try context.tool(named: "EncryptConfigCLI")

        return try makeCommands(
            projectDirectory: URL(fileURLWithPath: target.directory.string),
            workDirectory: context.pluginWorkDirectoryURL,
            tool: tool.url
        )
    }
}

#if canImport(XcodeProjectPlugin)
import XcodeProjectPlugin

extension EncryptConfigPlugin: XcodeBuildToolPlugin {

    func createBuildCommands(
        context: XcodePluginContext,
        target: XcodeTarget
    ) throws -> [Command] {
        
        let tool = try context.tool(named: "EncryptConfigCLI")

        return try makeCommands(
            projectDirectory: context.xcodeProject.directoryURL,
            workDirectory: context.pluginWorkDirectoryURL,
            tool: tool.url
        )
    }
}
#endif

private func makeCommands(
    projectDirectory: URL,
    workDirectory: URL,
    tool: URL
) throws -> [Command] {

    let configFile = projectDirectory
        .appendingPathComponent("encrypt-config.json")

    let configData = try Data(
        contentsOf: configFile
    )

    let config = try JSONDecoder().decode(
        PluginConfiguration.self,
        from: configData
    )

    let environmentFile = projectDirectory
        .appendingPathComponent(".encrypt-config-environment")

    let selectedEnvironment: String

    if FileManager.default.fileExists(
        atPath: environmentFile.path
    ) {
        let environment = try String(
            contentsOf: environmentFile,
            encoding: .utf8
        )
        .trimmingCharacters(in: .whitespacesAndNewlines)

        selectedEnvironment = environment.isEmpty
            ? config.defaultEnvironment
            : environment
    } else {
        selectedEnvironment = config.defaultEnvironment
    }
    
    guard let environmentConfiguration =
        config.environments[selectedEnvironment]
    else {
        throw PluginConfigurationError.environmentNotFound(
            selectedEnvironment
        )
    }

    let inputFile = resolveURL(
        environmentConfiguration.input,
        relativeTo: configFile.deletingLastPathComponent()
    )

    let symbol =
        config.symbol
        ?? "EncryptedConfigResource"

    let outputFile = workDirectory
        .appendingPathComponent("\(symbol).generated.swift")

    return [
        .buildCommand(
            displayName: """
            Encrypt configuration (\(selectedEnvironment))
            """,
            executable: tool,
            arguments: [
                "--config",
                configFile.path,

                "--environment",
                selectedEnvironment,

                "--output",
                outputFile.path,

                "--emit",
                "swift",

                "--symbol",
                symbol
            ],
            inputFiles: [
                configFile,
                inputFile
            ],
            outputFiles: [
                outputFile
            ]
        )
    ]
}

private func resolveURL(
    _ path: String,
    relativeTo configFileDirectory: URL
) -> URL {

    if path.hasPrefix("/") {
        return URL(fileURLWithPath: path)
    }

    return configFileDirectory
        .appendingPathComponent(path)
        .standardizedFileURL
}
