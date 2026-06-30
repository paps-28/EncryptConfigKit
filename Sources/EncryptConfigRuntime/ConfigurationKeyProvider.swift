//
//  ConfigurationKeyProvider.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra on 30/06/26.
//


import Foundation

public protocol ConfigurationKeyProvider {
    func configurationPassword() async throws -> String
}