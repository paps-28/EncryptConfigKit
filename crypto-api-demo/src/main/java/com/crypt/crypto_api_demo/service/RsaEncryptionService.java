package com.crypt.crypto_api_demo.service;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Service
public class RsaEncryptionService {

    public String encrypt(String plaintext, String publicKeyPem) throws Exception {

        return encrypt(plaintext, parsePublicKey(publicKeyPem).key());
    }

    public String encrypt(String plaintext, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(
            "RSA/ECB/OAEPWithSHA-512AndMGF1Padding"
        );

        OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, PSource.PSpecified.DEFAULT);

        cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParams);

        byte[] encrypted = cipher.doFinal(
            plaintext.getBytes(StandardCharsets.UTF_8)
        );

        return Base64.getEncoder().encodeToString(encrypted);
    }

    public record ParsedPublicKey(byte[] der, RSAPublicKey key) {}

    // Both controllers accept the original PEM/Base64 contract and use the same parser.
    public ParsedPublicKey parsePublicKey(String publicKeyPem) throws Exception {
        if (publicKeyPem == null || publicKeyPem.isBlank() || publicKeyPem.length() > 32_768) {
            throw new IllegalArgumentException("Invalid RSA public key");
        }
        String publicKeyBase64 = publicKeyPem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(publicKeyBase64);
        if (decoded.length == 0 || decoded.length > 16_384) {
            throw new IllegalArgumentException("Invalid RSA public key size");
        }

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        RSAPublicKey key = (RSAPublicKey) keyFactory.generatePublic(keySpec);
        // Keep the supplied DER bytes: App Attest signs those bytes, not a re-encoding.
        return new ParsedPublicKey(decoded, key);
    }
}
