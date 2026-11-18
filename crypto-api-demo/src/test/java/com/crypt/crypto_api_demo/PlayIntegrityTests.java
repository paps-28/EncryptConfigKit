package com.crypt.crypto_api_demo;

import com.crypt.crypto_api_demo.controller.*;
import com.crypt.crypto_api_demo.service.*;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.*;
import org.springframework.http.*;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.server.ResponseStatusException;
import java.security.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import javax.crypto.Cipher;
import javax.crypto.spec.*;
import java.security.spec.MGF1ParameterSpec;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class PlayIntegrityTests {
    static final ObjectMapper JSON = new ObjectMapper();
    static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-27T18:00:00Z"), ZoneOffset.UTC);
    static final String CERT = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]);
    static KeyPair rsa;
    static String publicKey;
    ChallengeService challenges;
    Decoder decoder;
    PlayIntegrityVerifier verifier;
    PlayIntegrityController controller;

    static class Decoder extends GoogleIntegrityDecoder {
        JsonNode payload;
        int calls;
        boolean unavailable;
        @Override public JsonNode decode(String name, String token) {
            calls++;
            if (unavailable) throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE);
            if (!"test-token".equals(token)) throw new ResponseStatusException(HttpStatus.FORBIDDEN);
            return payload;
        }
    }

    static class MutableClock extends Clock {
        Instant current = CLOCK.instant();
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return Clock.fixed(current, zone); }
        @Override public Instant instant() { return current; }
    }

    @BeforeAll static void keys() throws Exception {
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(3072);
        rsa = generator.generateKeyPair();
        publicKey = Base64.getEncoder().encodeToString(rsa.getPublic().getEncoded());
    }

    @BeforeEach void setup() {
        challenges = new ChallengeService(CLOCK);
        decoder = new Decoder();
        verifier = new PlayIntegrityVerifier(decoder, "test.application", CERT, 60, CLOCK);
        controller = new PlayIntegrityController(challenges, verifier, new RsaEncryptionService(), "AQMH");
    }

    private ChallengeService.Response challenge() throws Exception {
        var challenge = controller.challenge(Map.of());
        ObjectNode payload = JSON.createObjectNode();
        payload.putObject("requestDetails").put("requestPackageName", "test.application")
                .put("requestHash", PlayIntegrityVerifier.requestHash(Base64.getDecoder().decode(challenge.challenge()), rsa.getPublic().getEncoded()))
                .put("timestampMillis", Long.toString(CLOCK.millis()));
        payload.putObject("appIntegrity").put("packageName", "test.application").put("appRecognitionVerdict", "PLAY_RECOGNIZED")
                .putArray("certificateSha256Digest").add(CERT);
        payload.putObject("deviceIntegrity").putArray("deviceRecognitionVerdict").add("MEETS_DEVICE_INTEGRITY");
        payload.putObject("accountDetails").put("appLicensingVerdict", "LICENSED");
        decoder.payload = payload;
        return challenge;
    }

    private PlayIntegrityController.KeyRequest request(String id) {
        return new PlayIntegrityController.KeyRequest(id, publicKey, "test-token");
    }

    @Test void publicVector() throws Exception {
        var vector = JSON.readTree(getClass().getResourceAsStream("/play-integrity-vector.json"));
        assertEquals(vector.get("requestHash").asText(), PlayIntegrityVerifier.requestHash(
                Base64.getDecoder().decode(vector.get("challenge").asText()), Base64.getDecoder().decode(vector.get("publicKey").asText())));
    }

    @Test void acceptedProofWrapsBase64PasswordAndCannotReplay() throws Exception {
        var response = controller.publicKey(request(challenge().challengeId()));
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, rsa.getPrivate(), new OAEPParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, PSource.PSpecified.DEFAULT));
        assertEquals("AQMH", new String(cipher.doFinal(Base64.getDecoder().decode(response.encryptedKey())), java.nio.charset.StandardCharsets.UTF_8));
        var next = challenge();
        controller.publicKey(request(next.challengeId()));
        assertStatus(400, () -> controller.publicKey(request(next.challengeId())));
    }

    @Test void identityAndVerdictFailuresConsumeChallenge() throws Exception {
        for (String field : List.of("requestPackageName", "requestHash", "timestampMillis", "packageName", "certificateSha256Digest",
                "appRecognitionVerdict", "deviceRecognitionVerdict", "appLicensingVerdict")) {
            var challenge = challenge();
            for (JsonNode section : decoder.payload) if (section.has(field)) ((ObjectNode) section).put(field, "rejected");
            assertStatus(403, () -> controller.publicKey(request(challenge.challengeId())));
            assertStatus(400, () -> controller.publicKey(request(challenge.challengeId())));
        }
    }

    @Test void futureAndOldTokensRejected() throws Exception {
        for (long offset : new long[]{-300001, 30001}) {
            var challenge = challenge();
            ((ObjectNode) decoder.payload.get("requestDetails")).put("timestampMillis", Long.toString(CLOCK.millis() + offset));
            assertStatus(403, () -> controller.publicKey(request(challenge.challengeId())));
        }
    }

    @Test void rsaOrChallengeSubstitutionRejected() throws Exception {
        var first = challenge();
        var second = controller.challenge(Map.of());
        assertStatus(403, () -> controller.publicKey(request(second.challengeId())));
        var generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(3072);
        String other = Base64.getEncoder().encodeToString(generator.generateKeyPair().getPublic().getEncoded());
        assertStatus(403, () -> controller.publicKey(new PlayIntegrityController.KeyRequest(first.challengeId(), other, "test-token")));
    }

    @Test void googleFailureStillConsumesAndRetryUsesFreshProof() throws Exception {
        var first = challenge(); decoder.unavailable = true;
        assertStatus(503, () -> controller.publicKey(request(first.challengeId())));
        decoder.unavailable = false;
        assertStatus(400, () -> controller.publicKey(request(first.challengeId())));
        assertNotNull(controller.publicKey(request(challenge().challengeId())));
    }

    @Test void malformedProofRejectedBeforeGoogle() throws Exception {
        var id = challenge().challengeId();
        for (String token : Arrays.asList(null, "", "a".repeat(32769)))
            assertStatus(400, () -> controller.publicKey(new PlayIntegrityController.KeyRequest(id, publicKey, token)));
        assertStatus(400, () -> controller.publicKey(new PlayIntegrityController.KeyRequest(id, "AQ==", "test-token")));
        assertStatus(403, () -> controller.publicKey(new PlayIntegrityController.KeyRequest(id, publicKey, "invalid")));
        assertEquals(1, decoder.calls);
    }

    @Test void expiryPlatformPurposeAndConcurrentConsumption() throws Exception {
        var time = new MutableClock();
        var expiredStore = new ChallengeService(time);
        var expired = expiredStore.issue(ChallengeService.Operation.PLAY_INTEGRITY, null);
        time.current = time.current.plusSeconds(301);
        assertStatus(400, () -> expiredStore.consume(expired.challengeId(), ChallengeService.Operation.PLAY_INTEGRITY, null));
        var apple = challenges.issue(ChallengeService.Operation.APPLE_ATTESTATION, "key");
        String firstAppleId = apple.challengeId();
        assertStatus(400, () -> challenges.consume(firstAppleId, ChallengeService.Operation.PLAY_INTEGRITY, null));
        apple = challenges.issue(ChallengeService.Operation.APPLE_ATTESTATION, "key");
        String appleId = apple.challengeId();
        assertStatus(400, () -> challenges.consume(appleId, ChallengeService.Operation.APPLE_ASSERTION, "key"));
        var active = challenges.issue(ChallengeService.Operation.PLAY_INTEGRITY, null);
        assertEquals(CLOCK.instant().plusSeconds(300), active.expiresAt());
        assertEquals(32, Base64.getDecoder().decode(active.challenge()).length);
        try (var executor = Executors.newFixedThreadPool(2)) {
            Callable<Boolean> consume = () -> { try { challenges.consume(active.challengeId(), ChallengeService.Operation.PLAY_INTEGRITY, null); return true; }
                catch (ResponseStatusException e) { return false; } };
            var results = executor.invokeAll(List.of(consume, consume));
            assertNotEquals(results.get(0).get(), results.get(1).get());
        }
    }

    @Test void httpContractLegacyAndSizeLimit() throws Exception {
        var mvc = MockMvcBuilders.standaloneSetup(controller, new CryptoController()).addFilters(new IntegrityRequestFilter()).build();
        mvc.perform(post("/api/crypto/play-integrity/challenge").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isOk());
        mvc.perform(post("/api/crypto/play-integrity/challenge").contentType(MediaType.APPLICATION_JSON).content("{\"purpose\":\"ASSERTION\"}"))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/api/crypto/play-integrity/public-key").contentType(MediaType.APPLICATION_JSON).content(" ".repeat(65537)))
                .andExpect(status().isPayloadTooLarge());
        for (String path : List.of("public-key", "public-key-with-file"))
            mvc.perform(post("/api/crypto/" + path).contentType(MediaType.APPLICATION_JSON).content("{}"))
                    .andExpect(status().isGone());
    }

    @Test void absentConfigurationAndRateLimitFailClosed() throws Exception {
        var missing = new PlayIntegrityVerifier(decoder, "", "", 60, CLOCK);
        assertStatus(503, missing::requireConfigured);
        var noPassword = new PlayIntegrityController(challenges, verifier, new RsaEncryptionService(), "");
        assertStatus(503, () -> noPassword.challenge(Map.of()));
        var limited = new PlayIntegrityVerifier(decoder, "test.application", CERT, 1, CLOCK);
        var challenge = challenge(); byte[] bytes = Base64.getDecoder().decode(challenge.challenge());
        limited.verify("test-token", bytes, rsa.getPublic().getEncoded());
        assertStatus(429, () -> limited.verify("test-token", bytes, rsa.getPublic().getEncoded()));
        assertEquals(1, decoder.calls);
    }

    interface Action { void run() throws Exception; }
    static void assertStatus(int expected, Action action) {
        assertEquals(expected, assertThrows(ResponseStatusException.class, action::run).getStatusCode().value());
    }
}
