//
//  AppConfiguration.swift
//  encryptKeyTest
//
//  Created by Pedro Alberto Parra on 02/07/26.
//


struct AppConfiguration: Sendable, nonisolated Decodable {
    let HOST_NAME: String
    let CLIENT_ID: String
}
