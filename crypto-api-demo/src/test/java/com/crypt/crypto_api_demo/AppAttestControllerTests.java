package com.crypt.crypto_api_demo;

import com.crypt.crypto_api_demo.controller.AppAttestController;
import com.crypt.crypto_api_demo.service.AppAttestService;
import com.crypt.crypto_api_demo.service.AppAttestVerifier;
import com.crypt.crypto_api_demo.service.RsaEncryptionService;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.spec.MGF1ParameterSpec;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class AppAttestControllerTests {
    private static final String PREFIX = "/api/crypto/app-attest";
    private static final String KEY_ID = Base64.getEncoder().encodeToString(new byte[32]);

    @Test
    void challengeEndpointAcceptsJson() throws Exception {
        var mvc = MockMvcBuilders.standaloneSetup(controller("")).build();
        String response = mvc.perform(post(PREFIX + "/challenge").contentType(MediaType.APPLICATION_JSON)
                .content("{\"keyId\":\"" + KEY_ID + "\",\"purpose\":\"ATTESTATION\"}"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertTrue(response.contains("challengeId"));
        assertTrue(response.contains("expiresAt"));
    }

    @Test
    void endpointsRejectInvalidRequests() throws Exception {
        var mvc = MockMvcBuilders.standaloneSetup(controller("")).build();
        mvc.perform(post(PREFIX + "/challenge").contentType(MediaType.APPLICATION_JSON)
                .content("{\"keyId\":\"bad\",\"purpose\":\"ATTESTATION\"}"))
                .andExpect(status().isBadRequest());
        mvc.perform(post(PREFIX + "/attest").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest());
        mvc.perform(post(PREFIX + "/public-key").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isServiceUnavailable());
    }

    @Test
    void encryptsWithTheExactRsaBytesVerifiedByAssertion() throws Exception {
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        var key = generator.generateKeyPair();
        byte[][] verified = new byte[1][];
        var service = new AppAttestService(null) {
            @Override
            public synchronized void assertKey(String id, String challenge, String assertion, byte[] der) {
                verified[0] = der;
            }
        };
        String secret = "test-aes-key-base64";
        var controller = new AppAttestController(service, new RsaEncryptionService(), secret);
        String publicKey = Base64.getEncoder().encodeToString(key.getPublic().getEncoded());
        var response = controller.publicKey(new AppAttestController.AssertionRequest(
                KEY_ID, "challenge", "assertion", publicKey));
        assertArrayEquals(key.getPublic().getEncoded(), verified[0]);
        Cipher decryptor = Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding");
        decryptor.init(Cipher.DECRYPT_MODE, key.getPrivate(), new OAEPParameterSpec(
                "SHA-512", "MGF1", MGF1ParameterSpec.SHA512, PSource.PSpecified.DEFAULT));
        assertEquals(secret, new String(decryptor.doFinal(Base64.getDecoder().decode(response.encryptedKey())),
                StandardCharsets.UTF_8));
    }

    @Test
    void invalidRsaIsRejectedBeforeAssertionVerification() throws Exception {
        var mvc = MockMvcBuilders.standaloneSetup(controller("configured-key")).build();
        mvc.perform(post(PREFIX + "/public-key").contentType(MediaType.APPLICATION_JSON)
                .content("{\"keyId\":\"" + KEY_ID + "\",\"publicKey\":\"AQ==\"}"))
                .andExpect(status().isBadRequest());
    }

    private static AppAttestController controller(String aesKey) {
        var verifier = new AppAttestVerifier("TEAM.app", "production", "classpath:apple-app-attest-root.pem",
                new DefaultResourceLoader());
        return new AppAttestController(new AppAttestService(verifier), new RsaEncryptionService(), aesKey);
    }
}
