//
//  AppAttestManager.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra Solis on 10/10/26.
//

import Foundation
import DeviceCheck
import CryptoKit

public actor AppAttestManager {
    
    private let service = DCAppAttestService.shared
    private let keyStore: any AppAttestKeyStoring
    
    private var pendingKeyTask: Task<String, Error>?
    
    public init(keyStore: any AppAttestKeyStoring) {
        self.keyStore = keyStore
    }
    
    public var isSupported: Bool {
        service.isSupported
    }
    
    public func getOrCreateKeyId() async throws -> String {
        guard service.isSupported else {
            throw AppAttestError.notSupported
        }
        
        if let existing = try keyStore.loadKeyId() {
            return existing
        }
        
        if let pendingKeyTask {
            return try await pendingKeyTask.value
        }
        
        let task = Task<String, Error> {
            let keyId = try await service.generateKey()
            
            try keyStore.saveKeyId(keyId)
            return keyId
        }
        
        pendingKeyTask = task
        let result = await task.result
        pendingKeyTask = nil
        
        return try result.get()
    }
    
    public func currentKeyId() throws -> String? {
        try keyStore.loadKeyId()
    }
    
    public func generateAttestation(challenge: Data) async throws -> Data {
        
        guard !challenge.isEmpty else {
            throw AppAttestError.invalidChallenge
        }
        
        let keyId = try await getOrCreateKeyId()
        
        let clientDataHash = Data(SHA256.hash(data: challenge))
        
        return try await service.attestKey(keyId, clientDataHash: clientDataHash)
    }
    
    public func generateAssertion(challenge: Data, rsaPublicKey: Data) async throws -> Data {
        let keyId = try await getOrCreateKeyId()
        let clientDataHash = try AppAttestPayload.hash(challenge: challenge, rsaPublickKey: rsaPublicKey)
        
        return try await service.generateAssertion(keyId, clientDataHash: clientDataHash)
    }
    
    
}
