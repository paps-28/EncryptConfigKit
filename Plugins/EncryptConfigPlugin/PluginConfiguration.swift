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

        return try makeCommands(
            projectDirectory: target.directory,
            workDirectory: context.pluginWorkDirectory,
            tool: context.tool(named: "EncryptConfigCLI")
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

        try makeCommands(
            projectDirectory: context.xcodeProject.directory,
            workDirectory: context.pluginWorkDirectory,
            tool: context.tool(named: "EncryptConfigCLI")
        )
    }
}
#endif

private func makeCommands(
    projectDirectory: Path,
    workDirectory: Path,
    tool: PluginContext.Tool
) throws -> [Command] {

    let configFile = projectDirectory
        .appending("encrypt-config.json")

    let configData = try Data(
        contentsOf: URL(
            fileURLWithPath: configFile.string
        )
    )

    let config = try JSONDecoder().decode(
        PluginConfiguration.self,
        from: configData
    )

    let processEnvironment =
        ProcessInfo.processInfo.environment

    let selectedEnvironment =
        processEnvironment["CONFIG_ENV"]
        ?? config.defaultEnvironment

    guard let environmentConfiguration =
        config.environments[selectedEnvironment]
    else {
        throw PluginConfigurationError.environmentNotFound(
            selectedEnvironment
        )
    }

    let inputFile = resolvePath(
        environmentConfiguration.input,
        relativeTo: configFile
    )

    let symbol =
        config.symbol
        ?? "EncryptedConfigResource"

    let outputFile = workDirectory
        .appending("\(symbol).generated.swift")

    return [
        .buildCommand(
            displayName: """
            Encrypt configuration (\(selectedEnvironment))
            """,
            executable: tool.path,
            arguments: [
                "--config",
                configFile.string,

                "--environment",
                selectedEnvironment,

                "--output",
                outputFile.string,

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

private func resolvePath(
    _ path: String,
    relativeTo configFile: Path
) -> Path {

    if path.hasPrefix("/") {
        return Path(path)
    }

    /*
     El input del JSON se interpreta respecto a la carpeta
     donde se encuentra encrypt-config.json.
     */

    let configDirectory = configFile.removingLastComponent()

    return configDirectory.appending(path)
}
