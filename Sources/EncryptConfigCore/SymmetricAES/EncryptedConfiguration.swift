//
//  EncryptedConfiguration.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra on 30/06/26.
//


import Foundation

public struct EncryptedConfiguration: Codable, Sendable {
    public let salt: Data
    public let combined: Data
    public let hash: String

    public init(salt: Data, combined: Data, hash: String) {
        self.salt = salt
        self.combined = combined
        self.hash = hash
    }
}
