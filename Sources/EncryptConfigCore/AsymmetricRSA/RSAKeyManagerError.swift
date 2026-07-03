//
//  RSAKeyManagerError.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra on 03/07/26.
//

import Foundation

public enum RSAKeyManagerError: Error {
    case generationFailed
    case publicKeyNotFound
    case publicKeyExportFailed
    case privateKeyNotFound
    case saveFailed(OSStatus)
    case loadFailed(OSStatus)
    case deleteFailed(OSStatus)
}
