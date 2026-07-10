//
//  CLIError.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra on 10/07/26.
//


enum CLIError: Error {
    case missingRequiredArguments
    case invalidArguments(String)
    case missingEnvironmentKey(String)
    case environmentNotFound(String)
    case invalidConfigurationFile(String)
    case failedToEncodeSwiftSource

    var errorDescription: String? {
        switch self {
        case .missingRequiredArguments:
            return "Missing required CLI arguments."

        case .invalidArguments(let message):
            return message

        case .missingEnvironmentKey(let key):
            return """
            Environment variable '\(key)' is missing or empty.
            """

        case .environmentNotFound(let environment):
            return """
            Environment '\(environment)' was not found \
            in encrypt-config.json.
            """

        case .invalidConfigurationFile(let message):
            return "Invalid configuration file: \(message)"
            
        case .failedToEncodeSwiftSource:
            return "The generated Swift source could not be encoded as UTF-8."
        }
    }
}
