package com.crypt.crypto_api_demo.controller;


import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.crypt.crypto_api_demo.dto.*;
import com.crypt.crypto_api_demo.service.RsaEncryptionService;

@RestController
@RequestMapping("/api/crypto")
public class CryptoController {

    private final RsaEncryptionService rsaEncryptionService;
    private final String aesKeyDev = "eosqFMaSmizdHNGVuYsaGDFpJ2uCB2EGc7RGBm7IKfE";

    public CryptoController(
        RsaEncryptionService rsaEncryptionService
    ) {
        this.rsaEncryptionService = rsaEncryptionService;
    }

    @PostMapping("/public-key")
    public ResponseEntity<EncryptedKeyResponse> receivePublicKey(
        @RequestBody PublicKeyRequest request
    ) throws Exception {
        String publicKey = request.publicKey();

        String encryptedKey = rsaEncryptionService.encrypt(this.aesKeyDev, publicKey);

        return ResponseEntity.ok(
            new EncryptedKeyResponse(encryptedKey)
        );
    }
}
