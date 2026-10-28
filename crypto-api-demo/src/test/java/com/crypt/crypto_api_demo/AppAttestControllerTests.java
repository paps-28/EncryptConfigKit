package com.crypt.crypto_api_demo;

import com.crypt.crypto_api_demo.controller.AppAttestController;
import com.crypt.crypto_api_demo.controller.CryptoController;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.crypt.crypto_api_demo.service.AppAttestService;
import com.crypt.crypto_api_demo.service.AppAttestVerifier;
import com.crypt.crypto_api_demo.service.RsaEncryptionService;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.slf4j.LoggerFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.http.MediaType;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.util.Base64;
import java.util.Map;
import java.util.stream.Stream;

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

    @ParameterizedTest(name = "protected HTTP {0}")
    @MethodSource("com.crypt.crypto_api_demo.RsaEncryptionServiceTests#base64DerKeys")
    void protectedEndpointVerifiesExactDerBeforeEncrypting(String format, String publicKey, KeyPair key)
            throws Exception {
        int[] assertions = {0};
        var rsa = new CountingRsaService();
        var service = new AppAttestService(null) {
            @Override
            public synchronized void assertKey(String id, String challenge, String assertion, byte[] der) {
                assertEquals(KEY_ID, id);
                assertEquals("challenge", challenge);
                assertEquals("assertion", assertion);
                assertArrayEquals(key.getPublic().getEncoded(), der);
                assertEquals(0, rsa.encryptions);
                assertions[0]++;
            }
        };
        String secret = "protected-aes-key";
        var mvc = MockMvcBuilders.standaloneSetup(new AppAttestController(service, rsa, secret)).build();
        String response = mvc.perform(post(PREFIX + "/public-key").contentType(MediaType.APPLICATION_JSON)
                        .content(assertionJson(publicKey)))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertEquals(1, assertions[0]);
        assertEquals(1, rsa.encryptions);
        assertEquals(Base64.getEncoder().encodeToString(key.getPublic().getEncoded()), rsa.encryptionKey);
        assertEquals(secret, RsaEncryptionServiceTests.decrypt(
                new ObjectMapper().readTree(response).get("encryptedKey").asText(), key.getPrivate()));
    }

    @ParameterizedTest(name = "original HTTP {0}")
    @MethodSource("com.crypt.crypto_api_demo.RsaEncryptionServiceTests#publicKeyFormats")
    void originalEndpointStillEncryptsPemAndBase64(String format, String publicKey, KeyPair key) throws Exception {
        var mvc = MockMvcBuilders.standaloneSetup(new CryptoController(new RsaEncryptionService())).build();
        var json = new ObjectMapper();
        String response = mvc.perform(post("/api/crypto/public-key").contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("publicKey", publicKey))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertEquals("eosqFMaSmizdHNGVuYsaGDFpJ2uCB2EGc7RGBm7IKfE", RsaEncryptionServiceTests.decrypt(
                json.readTree(response).get("encryptedKey").asText(), key.getPrivate()));
    }

    @ParameterizedTest(name = "failed assertion {0}")
    @MethodSource("com.crypt.crypto_api_demo.RsaEncryptionServiceTests#base64DerKeys")
    void failedAssertionNeverEncrypts(String format, String publicKey, KeyPair key) throws Exception {
        int[] assertions = {0};
        var service = new AppAttestService(null) {
            @Override
            public synchronized void assertKey(String id, String challenge, String assertion, byte[] der) {
                assertArrayEquals(key.getPublic().getEncoded(), der);
                assertions[0]++;
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Invalid assertion");
            }
        };
        var rsa = new CountingRsaService();
        var mvc = MockMvcBuilders.standaloneSetup(new AppAttestController(service, rsa, "configured-key")).build();
        mvc.perform(post(PREFIX + "/public-key").contentType(MediaType.APPLICATION_JSON)
                        .content(assertionJson(publicKey)))
                .andExpect(status().isForbidden());
        assertEquals(1, assertions[0]);
        assertEquals(0, rsa.encryptions);
    }

    @ParameterizedTest(name = "invalid key {0}")
    @MethodSource("invalidPublicKeys")
    void invalidKeysNeverReachAssertionOrEncryption(String format, String publicKey) throws Exception {
        int[] assertions = {0};
        var service = new AppAttestService(null) {
            @Override
            public synchronized void assertKey(String id, String challenge, String assertion, byte[] der) {
                assertions[0]++;
            }
        };
        var rsa = new CountingRsaService();
        var mvc = MockMvcBuilders.standaloneSetup(new AppAttestController(service, rsa, "configured-key")).build();
        mvc.perform(post(PREFIX + "/public-key").contentType(MediaType.APPLICATION_JSON)
                        .content(assertionJson(publicKey)))
                .andExpect(status().isBadRequest());
        assertEquals(0, assertions[0]);
        assertEquals(0, rsa.encryptions);
    }

    @ParameterizedTest(name = "protected rejects text format {0}")
    @MethodSource("com.crypt.crypto_api_demo.RsaEncryptionServiceTests#nonDerTextFormats")
    void protectedEndpointRejectsPemAndWhitespace(String format, String publicKey, KeyPair key) throws Exception {
        invalidKeysNeverReachAssertionOrEncryption(format, publicKey);
    }

    static Stream<Arguments> invalidPublicKeys() throws Exception {
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        var weakKey = (RSAPublicKey) generator.generateKeyPair().getPublic();
        byte[] pkcs1 = new org.bouncycastle.asn1.pkcs.RSAPublicKey(
                weakKey.getModulus(), weakKey.getPublicExponent()).getEncoded();
        var ec = KeyPairGenerator.getInstance("EC");
        ec.initialize(256);
        String ecBase64 = Base64.getEncoder().encodeToString(ec.generateKeyPair().getPublic().getEncoded());
        var oversized = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(
                BigInteger.ONE.shiftLeft(8192).add(BigInteger.ONE), BigInteger.valueOf(65537)));
        return Stream.of(
                Arguments.of("invalid PEM", "-----BEGIN PUBLIC KEY-----\nnot!base64\n-----END PUBLIC KEY-----"),
                Arguments.of("invalid DER", "AQ=="),
                Arguments.of("empty PEM", "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----"),
                Arguments.of("PKCS1 PEM", "-----BEGIN RSA PUBLIC KEY-----\n"
                        + Base64.getEncoder().encodeToString(pkcs1) + "\n-----END RSA PUBLIC KEY-----"),
                Arguments.of("PKCS1 Base64", Base64.getEncoder().encodeToString(pkcs1)),
                Arguments.of("EC Base64", ecBase64),
                Arguments.of("EC PEM", "-----BEGIN PUBLIC KEY-----\n" + ecBase64 + "\n-----END PUBLIC KEY-----"),
                Arguments.of("RSA 1024", Base64.getEncoder().encodeToString(weakKey.getEncoded())),
                Arguments.of("RSA 8193", Base64.getEncoder().encodeToString(oversized.getEncoded())));
    }

    @ParameterizedTest(name = "missing proof {0}")
    @MethodSource("com.crypt.crypto_api_demo.RsaEncryptionServiceTests#publicKeyFormats")
    void realServiceDoesNotAllowMissingProof(String format, String publicKey, KeyPair key) throws Exception {
        var verifier = new AppAttestVerifier("TEAM.app", "production", "classpath:apple-app-attest-root.pem",
                new DefaultResourceLoader());
        var rsa = new CountingRsaService();
        var mvc = MockMvcBuilders.standaloneSetup(new AppAttestController(
                new AppAttestService(verifier), rsa, "configured-key")).build();
        mvc.perform(post(PREFIX + "/public-key").contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(Map.of("keyId", KEY_ID, "publicKey", publicKey))))
                .andExpect(status().isBadRequest());
        // Plausible proof fields cannot bypass the real challenge/credential checks either.
        mvc.perform(post(PREFIX + "/public-key").contentType(MediaType.APPLICATION_JSON)
                        .content(assertionJson(publicKey)))
                .andExpect(status().isBadRequest());
        assertEquals(0, rsa.encryptions);
    }

    @Test
    void logsOperationsAndFailuresWithoutSensitiveValuesOrThrowables() throws Exception {
        var logger = (Logger) LoggerFactory.getLogger("com.crypt.crypto_api_demo");
        Level previousLevel = logger.getLevel();
        var appender = new ListAppender<ILoggingEvent>();
        appender.start();
        logger.addAppender(appender);
        logger.setLevel(Level.DEBUG);
        try {
            var verifier = new AppAttestVerifier("TEAM.app", "production",
                    "classpath:apple-app-attest-root.pem", new DefaultResourceLoader()) {
                @Override
                public java.security.PublicKey verifyAttestation(String id, byte[] object, byte[] challenge) {
                    return null;
                }
                @Override
                public long verifyAssertion(java.security.PublicKey key, long counter, byte[] object,
                                            byte[] challenge, byte[] rsa) {
                    return counter + 1;
                }
            };
            var generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            String publicKey = Base64.getEncoder().encodeToString(generator.generateKeyPair().getPublic().getEncoded());
            String secret = "sensitive-aes-marker";
            String proof = Base64.getEncoder().encodeToString("sensitive-proof-marker".getBytes(StandardCharsets.UTF_8));
            var service = new AppAttestService(verifier);
            var controller = new AppAttestController(service, new RsaEncryptionService(), secret);
            var registration = controller.challenge(new AppAttestController.ChallengeRequest(
                    KEY_ID, AppAttestService.Purpose.ATTESTATION));
            controller.attest(new AppAttestController.AttestationRequest(KEY_ID, registration.challengeId(), proof));
            var challenge = controller.challenge(new AppAttestController.ChallengeRequest(
                    KEY_ID, AppAttestService.Purpose.ASSERTION));
            var request = new AppAttestController.AssertionRequest(KEY_ID, challenge.challengeId(), proof, publicKey);
            var response = controller.publicKey(request);
            var rejection = assertThrows(ResponseStatusException.class, () -> controller.publicKey(request));
            assertEquals(HttpStatus.BAD_REQUEST, rejection.getStatusCode());

            var failingRsa = new RsaEncryptionService() {
                @Override
                public String encrypt(String plaintext, String key) {
                    throw new IllegalStateException("sensitive-unexpected-message " + plaintext + key);
                }
            };
            var next = controller.challenge(new AppAttestController.ChallengeRequest(KEY_ID, AppAttestService.Purpose.ASSERTION));
            assertThrows(IllegalStateException.class, () -> new AppAttestController(service, failingRsa, secret)
                    .publicKey(new AppAttestController.AssertionRequest(KEY_ID, next.challengeId(), proof, publicKey)));
            assertThrows(ResponseStatusException.class, () -> new AppAttestController(service, failingRsa, "")
                    .publicKey(request));
            assertThrows(ResponseStatusException.class, () -> controller.publicKey(
                    new AppAttestController.AssertionRequest(KEY_ID, next.challengeId(), proof, "invalid-rsa-marker")));

            String logs = appender.list.stream().map(ILoggingEvent::getFormattedMessage)
                    .collect(java.util.stream.Collectors.joining("\n"));
            for (String operation : new String[]{"challenge", "register", "assertion", "encryption"}) {
                assertTrue(logs.contains(operation + " start"));
                assertTrue(logs.contains(operation + " success"));
            }
            assertTrue(appender.list.stream().anyMatch(event -> event.getLevel() == Level.WARN
                    && event.getFormattedMessage().contains("reason=Challenge is expired, consumed or does not match this operation")));
            assertTrue(appender.list.stream().anyMatch(event -> event.getLevel() == Level.ERROR
                    && event.getFormattedMessage().contains("exceptionClass=java.lang.IllegalStateException")));
            for (String sensitive : new String[]{KEY_ID, registration.challengeId(), registration.challenge(),
                    challenge.challengeId(), challenge.challenge(), next.challengeId(), next.challenge(),
                    secret, proof, publicKey, response.encryptedKey(), "sensitive-proof-marker",
                    "sensitive-unexpected-message", "invalid-rsa-marker"}) {
                assertFalse(logs.contains(sensitive));
            }
            assertTrue(appender.list.stream().allMatch(event -> event.getThrowableProxy() == null));
        } finally {
            logger.detachAppender(appender);
            logger.setLevel(previousLevel);
            appender.stop();
        }
    }

    private static String assertionJson(String publicKey) throws Exception {
        return new ObjectMapper().writeValueAsString(new AppAttestController.AssertionRequest(
                KEY_ID, "challenge", "assertion", publicKey));
    }

    private static class CountingRsaService extends RsaEncryptionService {
        private int encryptions;
        private String encryptionKey;

        @Override
        public String encrypt(String plaintext, String publicKey) throws Exception {
            encryptions++;
            encryptionKey = publicKey;
            return super.encrypt(plaintext, publicKey);
        }
    }

    private static AppAttestController controller(String aesKey) {
        var verifier = new AppAttestVerifier("TEAM.app", "production", "classpath:apple-app-attest-root.pem",
                new DefaultResourceLoader());
        return new AppAttestController(new AppAttestService(verifier), new RsaEncryptionService(), aesKey);
    }
}
