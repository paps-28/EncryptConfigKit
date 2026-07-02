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

        let configFile = target.directory.appending("encrypt-config.json")

        let configData = try Data(
            contentsOf: URL(fileURLWithPath: configFile.string)
        )

        let config = try JSONDecoder().decode(
            PluginConfiguration.self,
            from: configData
        )

        let inputFile = target.directory.appending(config.input)

        let outputFile = context.pluginWorkDirectory
            .appending("\(config.symbol).generated.swift")

        let tool = try context.tool(named: "encrypt-config")

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
}