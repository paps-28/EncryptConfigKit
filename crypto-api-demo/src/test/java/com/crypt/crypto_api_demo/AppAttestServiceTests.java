package com.crypt.crypto_api_demo;

import com.crypt.crypto_api_demo.service.AppAttestService;
import com.crypt.crypto_api_demo.service.AppAttestVerifier;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Base64;

import static com.crypt.crypto_api_demo.service.AppAttestService.Purpose.*;
import static org.junit.jupiter.api.Assertions.*;

class AppAttestServiceTests {
    private static final String KEY_ID = Base64.getEncoder().encodeToString(new byte[32]);
    private static final String OBJECT = "AQ==";

    @Test
    void createsRandomChallengesWithFiveMinuteExpiry() {
        var service = new AppAttestService(new StubVerifier());
        var first = service.challenge(KEY_ID, ATTESTATION);
        var second = service.challenge(KEY_ID, ATTESTATION);
        assertEquals(32, Base64.getDecoder().decode(first.challenge()).length);
        assertNotEquals(first.challenge(), second.challenge());
        assertNotEquals(first.challengeId(), second.challengeId());
        assertTrue(first.expiresAt().isAfter(java.time.Instant.now().plusSeconds(290)));
    }

    @Test
    void registrationCannotBeReplayedOrOverwritten() {
        var service = new AppAttestService(new StubVerifier());
        var challenge = service.challenge(KEY_ID, ATTESTATION);
        service.attest(KEY_ID, challenge.challengeId(), OBJECT);
        status(HttpStatus.BAD_REQUEST, () -> service.attest(KEY_ID, challenge.challengeId(), OBJECT));
        status(HttpStatus.CONFLICT, () -> service.challenge(KEY_ID, ATTESTATION));
        assertNotNull(service.challenge(KEY_ID, ASSERTION));
    }

    @Test
    void assertionsRequireARegisteredKey() {
        var service = new AppAttestService(new StubVerifier());
        status(HttpStatus.NOT_FOUND, () -> service.challenge(KEY_ID, ASSERTION));
    }

    @Test
    void failedVerificationStillConsumesChallenge() {
        var verifier = new StubVerifier();
        verifier.reject = true;
        var service = new AppAttestService(verifier);
        var challenge = service.challenge(KEY_ID, ATTESTATION);
        status(HttpStatus.FORBIDDEN, () -> service.attest(KEY_ID, challenge.challengeId(), OBJECT));
        verifier.reject = false;
        status(HttpStatus.BAD_REQUEST, () -> service.attest(KEY_ID, challenge.challengeId(), OBJECT));
    }

    @Test
    void challengeIsBoundToKeyAndPurpose() {
        var service = new AppAttestService(new StubVerifier());
        byte[] other = new byte[32];
        other[0] = 1;
        String otherId = Base64.getEncoder().encodeToString(other);
        var challenge = service.challenge(KEY_ID, ATTESTATION);
        status(HttpStatus.BAD_REQUEST, () -> service.attest(otherId, challenge.challengeId(), OBJECT));
        String id = service.challenge(KEY_ID, ATTESTATION).challengeId();
        status(HttpStatus.BAD_REQUEST, () -> service.assertKey(KEY_ID, id, OBJECT, new byte[]{1}));
    }

    @Test
    void countersArePersistedAndAssertionChallengesAreSingleUse() {
        var verifier = new StubVerifier();
        var service = new AppAttestService(verifier);
        service.attest(KEY_ID, service.challenge(KEY_ID, ATTESTATION).challengeId(), OBJECT);
        var first = service.challenge(KEY_ID, ASSERTION);
        service.assertKey(KEY_ID, first.challengeId(), OBJECT, new byte[]{1});
        assertEquals(0, verifier.previousCounter);
        status(HttpStatus.BAD_REQUEST, () -> service.assertKey(KEY_ID, first.challengeId(), OBJECT, new byte[]{1}));
        service.assertKey(KEY_ID, service.challenge(KEY_ID, ASSERTION).challengeId(), OBJECT, new byte[]{1});
        assertEquals(1, verifier.previousCounter);
    }

    @Test
    void rejectsMalformedAndOversizedInputs() {
        var service = new AppAttestService(new StubVerifier());
        status(HttpStatus.BAD_REQUEST, () -> service.challenge(null, ATTESTATION));
        status(HttpStatus.BAD_REQUEST, () -> service.challenge("!", ATTESTATION));
        status(HttpStatus.BAD_REQUEST, () -> service.challenge(KEY_ID, null));
        status(HttpStatus.BAD_REQUEST, () -> AppAttestService.decode("A".repeat(100), 3, "test"));
        status(HttpStatus.BAD_REQUEST, () -> AppAttestService.decode("!", 3, "test"));
    }

    private static void status(HttpStatus expected, Runnable action) {
        assertEquals(expected, assertThrows(ResponseStatusException.class, action::run).getStatusCode());
    }

    private static class StubVerifier extends AppAttestVerifier {
        boolean reject;
        long previousCounter;
        StubVerifier() {
            super("TEAM.app", "production", "classpath:apple-app-attest-root.pem", new DefaultResourceLoader());
        }
        @Override
        public PublicKey verifyAttestation(String id, byte[] object, byte[] challenge) {
            if (reject) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN);
            }
            try {
                return KeyPairGenerator.getInstance("EC").generateKeyPair().getPublic();
            } catch (Exception e) {
                throw new AssertionError(e);
            }
        }
        @Override
        public long verifyAssertion(PublicKey key, long counter, byte[] object, byte[] challenge, byte[] rsa) {
            previousCounter = counter;
            return counter + 1;
        }
    }
}
