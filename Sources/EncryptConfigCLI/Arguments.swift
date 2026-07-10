//
//  Arguments.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra on 02/07/26.
//


import Foundation

struct Arguments {

    let config: String?
    let environment: String?

    let input: String?
    let output: String

    let emit: EmitMode
    let symbol: String
    let keyEnvironment: String?

    enum EmitMode: String {
        case json
        case swift
    }

    init(arguments: [String] = CommandLine.arguments) throws {
        self.config = Self.value(
            after: "--config",
            in: arguments
        )

        self.environment = Self.value(
            after: "--environment",
            in: arguments
        )

        self.input = Self.value(
            after: "--input",
            in: arguments
        )

        guard let output = Self.value(
            after: "--output",
            in: arguments
        ) else {
            throw CLIError.missingRequiredArguments
        }

        self.output = output

        self.emit = EmitMode(
            rawValue: Self.value(
                after: "--emit",
                in: arguments
            ) ?? "json"
        ) ?? .json

        self.symbol = Self.value(
            after: "--symbol",
            in: arguments
        ) ?? "EncryptedConfigResource"

        self.keyEnvironment = Self.value(
            after: "--key-env",
            in: arguments
        )

        try validate()
    }

    private func validate() throws {
        let usesConfigFile = config != nil
        let usesLegacyArguments =
            input != nil &&
            keyEnvironment != nil

        guard usesConfigFile || usesLegacyArguments else {
            throw CLIError.invalidArguments(
                """
                Provide either:

                --config <encrypt-config.json>

                or:

                --input <file> --key-env <environment-variable>
                """
            )
        }
    }

    private static func value(
        after flag: String,
        in arguments: [String]
    ) -> String? {
        guard let index = arguments.firstIndex(of: flag) else {
            return nil
        }

        let valueIndex = arguments.index(after: index)

        guard arguments.indices.contains(valueIndex) else {
            return nil
        }

        let value = arguments[valueIndex]

        guard !value.hasPrefix("--") else {
            return nil
        }

        return value
    }
}
