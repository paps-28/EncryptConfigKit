package com.crypt.crypto_api_demo.controller;

import com.crypt.crypto_api_demo.dto.EncryptedKeyResponse;
import com.crypt.crypto_api_demo.service.*;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/crypto/play-integrity")
public class PlayIntegrityController {
    public record KeyRequest(String challengeId, String publicKey, String integrityToken) {}
    private final ChallengeService challenges;
    private final PlayIntegrityVerifier verifier;
    private final RsaEncryptionService rsa;
    private final String password;

    public PlayIntegrityController(ChallengeService challenges, PlayIntegrityVerifier verifier,
                                   RsaEncryptionService rsa, @Value("${play-integrity.password-base64:}") String password) {
        this.challenges = challenges;
        this.verifier = verifier;
        this.rsa = rsa;
        this.password = password;
    }

    @PostMapping("/challenge")
    public ChallengeService.Response challenge(@RequestBody Map<String, Object> request) {
        if (!request.isEmpty()) throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        configured();
        return challenges.issue(ChallengeService.Operation.PLAY_INTEGRITY, null);
    }

    @PostMapping("/public-key")
    public EncryptedKeyResponse publicKey(@RequestBody KeyRequest request) throws Exception {
        configured();
        if (request.integrityToken() == null || request.integrityToken().isBlank()
                || request.integrityToken().length() > 32_768)
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid integrityToken");
        byte[] der = AppAttestService.decode(request.publicKey(), 1024, "publicKey");
        try {
            RSAPublicKey key = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
            if (key.getModulus().bitLength() != 3072 || !key.getPublicExponent().equals(BigInteger.valueOf(65537))
                    || !Arrays.equals(key.getEncoded(), der) || !Base64.getEncoder().encodeToString(der).equals(request.publicKey()))
                throw new IllegalArgumentException();
        } catch (Exception e) { throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid RSA SPKI"); }
        byte[] challenge = challenges.consume(request.challengeId(), ChallengeService.Operation.PLAY_INTEGRITY, null);
        try {
            verifier.verify(request.integrityToken(), challenge, der);
            return new EncryptedKeyResponse(rsa.encrypt(password, request.publicKey()));
        } finally { Arrays.fill(challenge, (byte) 0); }
    }

    private void configured() {
        verifier.requireConfigured();
        byte[] decoded = null;
        try {
            decoded = Base64.getDecoder().decode(password);
            if (decoded.length == 0 || password.length() > 254
                    || !Base64.getEncoder().encodeToString(decoded).equals(password)) throw new IllegalArgumentException();
        } catch (Exception e) { throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Password is not configured"); }
        finally { if (decoded != null) Arrays.fill(decoded, (byte) 0); }
    }
}
