//
//  EncryptConfigCommand.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra on 02/07/26.
//


import EncryptConfigCore
import Foundation

struct EncryptConfigCommand {

    func run(arguments: Arguments) throws {
        let environment = ProcessInfo.processInfo.environment

        guard
            let password = environment[arguments.keyEnvironment],
            !password.isEmpty
        else {
            throw CLIError.missingEnvironmentKey(arguments.keyEnvironment)
        }

        let inputURL = URL(fileURLWithPath: arguments.input)
        let outputURL = URL(fileURLWithPath: arguments.output)

        let inputData = try Data(contentsOf: inputURL)

        let encrypted = try EncryptionService().encrypt(
            data: inputData,
            password: password
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]

        let encryptedData = try encoder.encode(encrypted)

        try FileManager.default.createDirectory(
            at: outputURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )

        switch arguments.emit {
        case .json:
            try encryptedData.write(to: outputURL)

        case .swift:
            let base64 = encryptedData.base64EncodedString()

            let source = """
            import Foundation

            enum \(arguments.symbol) {
                static let data = Data(base64Encoded: "\(base64)")!
            }
            """

            try source.write(
                to: outputURL,
                atomically: true,
                encoding: .utf8
            )
        }

        print("Encrypted config generated at: \(arguments.output)")
    }
}