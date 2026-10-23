package com.crypt.crypto_api_demo.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AppAttestSignatureTests {
    // Published assertion, public key and exact payload from the pinned upstream fixture:
    // https://raw.githubusercontent.com/uebelack/node-app-attest/f16c4bb71b737466872bc8b8a7dfd215364eaa83/test/verifyAssertion.test.js
    private static final String ASSERTION_BASE64 =
            "omlzaWduYXR1cmVYRzBFAiBB8BGAwkmFCg1M5J0mOYEun0SUN1/lse79/7ypG9WiMQIhAIHvqj7eg59B1PMFX1CN4GMGlsgfFtdL30pHCf7G/dNRcWF1dGhlbnRpY2F0b3JEYXRhWCXKPdw7T3iujcFZbHVrHX0mDSMrNms5PzEbrFbQPRA6rEAAAAAB";
    private static final String PUBLIC_KEY_PEM =
            "-----BEGIN PUBLIC KEY-----\n"
                    + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEg69t2YzgcPTLUx8Zgu+rbcikeaEL\n"
                    + "8Ppb+HG0QTIulz8YUB9tgv1pDRruWk87nZC3our56pzIWaqXEbaWyamdzA==\n"
                    + "-----END PUBLIC KEY-----\n";
    private static final String PAYLOAD =
            "{\"subject\":\"Lorem ipsum\",\"message\":\"Lorem ipsum dolor sit amet, consectetur adipiscing elit.\"}";

    private ECPublicKey publicKey;
    private byte[] authData;
    private byte[] clientDataHash;
    private byte[] signature;

    @BeforeEach
    void loadPublishedFixture() throws Exception {
        ObjectMapper cbor = new ObjectMapper(new CBORFactory());
        JsonNode assertion = cbor.readTree(Base64.getDecoder().decode(ASSERTION_BASE64));
        authData = assertion.get("authenticatorData").binaryValue();
        signature = assertion.get("signature").binaryValue();
        clientDataHash = MessageDigest.getInstance("SHA-256")
                .digest(PAYLOAD.getBytes(StandardCharsets.UTF_8));

        String encodedKey = PUBLIC_KEY_PEM
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        publicKey = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(
                new X509EncodedKeySpec(Base64.getDecoder().decode(encodedKey)));
    }

    @Test
    void acceptsPublishedSignatureOverNonce() throws Exception {
        assertTrue(AppAttestVerifier.verifyAssertionSignature(
                publicKey, authData, clientDataHash, signature));
    }

    @Test
    void rejectsWrongPayload() throws Exception {
        byte[] wrongClientDataHash = MessageDigest.getInstance("SHA-256")
                .digest("{}".getBytes(StandardCharsets.UTF_8));

        assertFalse(AppAttestVerifier.verifyAssertionSignature(
                publicKey, authData, wrongClientDataHash, signature));
    }

    @Test
    void rejectsChangedAtFlagWithoutNormalizingSignedBytes() throws Exception {
        byte[] changedAuthData = authData.clone();
        changedAuthData[32] ^= 0x40;

        assertFalse(AppAttestVerifier.verifyAssertionSignature(
                publicKey, changedAuthData, clientDataHash, signature));
    }

    @Test
    void rejectsPublishedSignatureWhenVerifyingConcatenationDirectly() throws Exception {
        // SHA256withECDSA must consume SHA256(authData || clientDataHash), not the concatenation.
        Signature directVerifier = Signature.getInstance("SHA256withECDSA");
        directVerifier.initVerify(publicKey);
        directVerifier.update(authData);
        directVerifier.update(clientDataHash);

        assertFalse(directVerifier.verify(signature));
    }
}
