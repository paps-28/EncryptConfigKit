//
//  Arguments.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra on 02/07/26.
//


import Foundation

struct Arguments {

    let input: String
    let output: String
    let emit: EmitMode
    let symbol: String
    let keyEnvironment: String

    enum EmitMode: String {
        case json
        case swift
    }

    init(arguments: [String] = CommandLine.arguments) throws {
        guard
            let input = Self.value(after: "--input", in: arguments),
            let output = Self.value(after: "--output", in: arguments)
        else {
            throw CLIError.missingRequiredArguments
        }

        self.input = input
        self.output = output
        self.emit = EmitMode(
            rawValue: Self.value(after: "--emit", in: arguments) ?? "json"
        ) ?? .json

        self.symbol = Self.value(after: "--symbol", in: arguments)
            ?? "EncryptedConfigResource"

        self.keyEnvironment = Self.value(after: "--key-env", in: arguments)
            ?? "CONFIG_KEY"
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

        return arguments[valueIndex]
    }
}

enum CLIError: Error {
    case missingRequiredArguments
    case missingEnvironmentKey(String)
}