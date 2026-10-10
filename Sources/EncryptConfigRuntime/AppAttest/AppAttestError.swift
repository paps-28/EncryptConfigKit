//
//  AppAttestError.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra Solis on 10/10/26.
//

import Foundation

public enum AppAttestError: Error, Sendable {
    case notSupported
    case invalidChallenge
    case invalidPublicKey
    case invalidKeyStoreId
    case keychainError(OSStatus)
}
