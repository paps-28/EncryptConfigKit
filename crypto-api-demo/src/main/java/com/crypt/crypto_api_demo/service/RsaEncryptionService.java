package com.crypt.crypto_api_demo.service;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Service
public class RsaEncryptionService {

    public String encrypt(String plaintext, String publicKeyPem) throws Exception {

        PublicKey publicKey = loadPublicKey(publicKeyPem);

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

    private PublicKey loadPublicKey(String publicKeyPem) throws Exception {

        String publicKeyBase64 = publicKeyPem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(publicKeyBase64);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePublic(keySpec);
    }
}
