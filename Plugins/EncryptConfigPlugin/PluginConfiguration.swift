//
//  PluginConfiguration.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra on 02/07/26.
//


import PackagePlugin
import Foundation

struct PluginConfiguration: Decodable {
    let input: String
    let symbol: String
    let keyEnvironment: String
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
            tool: context.tool(named: "encrypt-config")
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

        return try makeCommands(
            projectDirectory: context.xcodeProject.directory,
            workDirectory: context.pluginWorkDirectory,
            tool: context.tool(named: "encrypt-config")
        )
    }
}
#endif

private func makeCommands(
    projectDirectory: Path,
    workDirectory: Path,
    tool: PluginContext.Tool
) throws -> [Command] {

    let configFile = projectDirectory.appending("encrypt-config.json")

    let configData = try Data(
        contentsOf: URL(fileURLWithPath: configFile.string)
    )

    let config = try JSONDecoder().decode(
        PluginConfiguration.self,
        from: configData
    )

    let inputFile = projectDirectory.appending(config.input)

    let outputFile = workDirectory
        .appending("\(config.symbol).generated.swift")

    return [
        .buildCommand(
            displayName: "Encrypt \(config.input)",
            executable: tool.path,
            arguments: [
                "--input", inputFile.string,
                "--output", outputFile.string,
                "--emit", "swift",
                "--symbol", config.symbol,
                "--key-env", config.keyEnvironment
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
