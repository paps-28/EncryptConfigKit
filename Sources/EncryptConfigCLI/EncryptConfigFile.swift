//
//  EncryptConfigFile.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra on 10/07/26.
//


struct EncryptConfigFile: Decodable {
    let defaultEnvironment: String
    let environments: [String: EnvironmentConfig]
}

struct EnvironmentConfig: Decodable {
    let input: String
    let keyId: String?
    let keyEnvironmentVariable: String
}
