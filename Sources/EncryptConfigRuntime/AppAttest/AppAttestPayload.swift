//
//  AppAttestPayload.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra Solis on 10/10/26.
//

import Foundation
import CryptoKit

public enum AppAttestPayload {
    
    private static let domain = Data(
        "EncryptConfigKit.AppAttest.AESKey.v1".utf8
    )
    
    public static func make(
        challenge: Data,
        rsaPublicKey: Data
    ) throws -> Data {
        
        guard !challenge.isEmpty else {
            throw AppAttestError.invalidChallenge
        }
        
        guard !rsaPublicKey.isEmpty else {
            throw AppAttestError.invalidPublicKey
        }
        
        var payload = Data()
        
        payload.append(domain)
        payload.append(0)
        
        guard challenge.count <= Int(UInt32.max) else {
            throw AppAttestError.invalidChallenge
        }
        
        payload.append(challenge)
        payload.append(rsaPublicKey)
        
        return payload
    }
    
    public static func hash(
        challenge: Data,
        rsaPublickKey: Data
    ) throws -> Data {
        let payload = try AppAttestPayload.make(challenge: challenge,
                                                rsaPublicKey: rsaPublickKey)
                                            
        return Data(SHA256.hash(data: payload))
    }
}

            
