//
//  RemoteKeyProvider.swift
//  encryptKeyTest
//
//  Created by Pedro Alberto Parra Solis on 23/09/26.
//

import EncryptConfigCore
import EncryptConfigRuntime
import Security
import Foundation

struct RemoteKeyProvider: ConfigurationKeyProvider {
    
    private let apiClient: APIClient = .init()
    private let apiCipherPath: String = "/api/crypto/public-key"
    private let rsaProvider = RSAKeyManager(algorithm: .rsaEncryptionOAEPSHA512)

    func configurationPassword() async throws -> String {
        try rsaProvider.generateKeyPairIfNeeded()
        let rsaPublicKey = try rsaProvider.publicKeyPEM()
        
        let cipherResponse: EncryptedKeyResponseDTO = try await apiClient.post(endpoint: apiCipherPath, body: PublicKeyRequestDTO(publicKey: rsaPublicKey))
        
        let decryptedResponse = try rsaProvider.decrypt(Data(base64Encoded: cipherResponse.encryptedKey)!)
        let decryptedString = String(data: decryptedResponse, encoding: .utf8)
        
        return decryptedString!
    }
}
