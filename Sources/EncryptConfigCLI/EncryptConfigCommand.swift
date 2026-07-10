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
        let processEnvironment =
            ProcessInfo.processInfo.environment

        let resolvedConfiguration = try resolveConfiguration(
            arguments: arguments,
            processEnvironment: processEnvironment
        )

        guard
            let password = processEnvironment[
                resolvedConfiguration.keyEnvironmentVariable
            ],
            !password.isEmpty
        else {
            throw CLIError.missingEnvironmentKey(
                resolvedConfiguration.keyEnvironmentVariable
            )
        }

        let inputURL = URL(
            fileURLWithPath: resolvedConfiguration.input
        )

        let outputURL = URL(
            fileURLWithPath: arguments.output
        )

        let inputData = try Data(
            contentsOf: inputURL
        )

        let encrypted = try EncryptionService().encrypt(
            data: inputData,
            password: password
        )

        try FileManager.default.createDirectory(
            at: outputURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )

        try writeSwiftSource(
            encrypted,
            symbol: arguments.symbol,
            to: outputURL
        )

        print("Environment: \(resolvedConfiguration.environment)")
        print("Input: \(inputURL.path)")
        print("Output: \(outputURL.path)")
        print(
            "Key environment variable: " +
            resolvedConfiguration.keyEnvironmentVariable
        )

        if let keyId = resolvedConfiguration.keyId {
            print("Key ID: \(keyId)")
        }
    }
}

private func writeSwiftSource(
    _ encryptedConfiguration: EncryptedConfiguration,
    symbol: String,
    to outputURL: URL
) throws {
    let salt = encryptedConfiguration.salt
        .base64EncodedString()

    let combined = encryptedConfiguration.combined
        .base64EncodedString()

    let source = """
    import Foundation
    import EncryptConfigCore

    enum \(symbol) {
        static let value = EncryptedConfiguration(
            salt: Data(base64Encoded: "\(salt)")!,
            combined: Data(base64Encoded: "\(combined)")!
        )
    }
    """

    guard let data = source.data(using: .utf8) else {
        throw CLIError.failedToEncodeSwiftSource
    }

    try data.write(
        to: outputURL,
        options: .atomic
    )
}
