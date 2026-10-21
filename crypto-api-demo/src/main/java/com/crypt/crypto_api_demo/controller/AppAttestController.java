package com.crypt.crypto_api_demo.controller;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import com.crypt.crypto_api_demo.dto.EncryptedKeyResponse;
import com.crypt.crypto_api_demo.service.AppAttestService;
import com.crypt.crypto_api_demo.service.RsaEncryptionService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/crypto/app-attest")
public class AppAttestController {
    public record ChallengeRequest(String keyId, AppAttestService.Purpose purpose) {}
    public record AttestationRequest(String keyId, String challengeId, String attestationObject) {}
    public record AssertionRequest(String keyId, String challengeId, String assertionObject, String publicKey) {}

    private final AppAttestService appAttest;
    private final RsaEncryptionService rsa;
    private final String aesKey;

    public AppAttestController(AppAttestService appAttest, RsaEncryptionService rsa,
                              @Value("${app-attest.aes-key:}") String aesKey) {
        this.appAttest = appAttest;
        this.rsa = rsa;
        this.aesKey = aesKey;
    }

    @PostMapping("/challenge")
    public AppAttestService.ChallengeResponse challenge(@RequestBody ChallengeRequest request) {
        return appAttest.challenge(request.keyId(), request.purpose());
    }

    @PostMapping("/attest")
    public ResponseEntity<Void> attest(@RequestBody AttestationRequest request) {
        appAttest.attest(request.keyId(), request.challengeId(), request.attestationObject());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/public-key")
    public EncryptedKeyResponse publicKey(@RequestBody AssertionRequest request) throws Exception {
        if (aesKey.isBlank()) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "App Attest AES key is not configured");
        }
        // The exact DER bytes hashed by Swift are also the key used for encryption.
        byte[] der = AppAttestService.decode(request.publicKey(), 16_384, "publicKey");
        try {
            RSAPublicKey key = (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(der));
            if (key.getModulus().bitLength() < 2048 || key.getModulus().bitLength() > 8192) {
                throw new IllegalArgumentException("Invalid RSA size");
            }
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "publicKey must be a Base64 DER X.509 RSA key (2048–8192 bits)");
        }
        appAttest.assertKey(request.keyId(), request.challengeId(), request.assertionObject(), der);
        return new EncryptedKeyResponse(rsa.encrypt(aesKey, Base64.getEncoder().encodeToString(der)));
    }
}
