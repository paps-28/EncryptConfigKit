package com.crypt.crypto_api_demo.service;

import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AppAttestService {
    public enum Purpose { ATTESTATION, ASSERTION }
    public record ChallengeResponse(String challengeId, String challenge, Instant expiresAt) {}
    private record Challenge(String keyId, Purpose purpose, byte[] value, Instant expiresAt) {}
    private record Credential(PublicKey publicKey, long counter) {}

    private static final int MAX_ENTRIES = 10_000;
    private final Map<String, Challenge> challenges = new HashMap<>();
    private final Map<String, Credential> credentials = new HashMap<>();
    private final AppAttestVerifier verifier;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();

    @Autowired
    public AppAttestService(AppAttestVerifier verifier) {
        this(verifier, Clock.systemUTC());
    }

    AppAttestService(AppAttestVerifier verifier, Clock clock) {
        this.verifier = verifier;
        this.clock = clock;
    }

    // In-memory demo storage: synchronization makes challenge consumption and counters atomic.
    public synchronized ChallengeResponse challenge(String keyId, Purpose purpose) {
        validateKeyId(keyId);
        if (purpose == null) {
            throw badRequest("purpose is required");
        }
        if (purpose == Purpose.ASSERTION && !credentials.containsKey(keyId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "App Attest key is not registered");
        }
        if (purpose == Purpose.ATTESTATION && credentials.containsKey(keyId)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "App Attest key is already registered");
        }
        Instant now = clock.instant();
        challenges.values().removeIf(value -> !value.expiresAt().isAfter(now));
        if (challenges.size() >= MAX_ENTRIES) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Too many pending challenges");
        }
        byte[] value = new byte[32];
        random.nextBytes(value);
        String id = UUID.randomUUID().toString();
        Instant expiresAt = now.plus(Duration.ofMinutes(5));
        challenges.put(id, new Challenge(keyId, purpose, value, expiresAt));
        return new ChallengeResponse(id, Base64.getEncoder().encodeToString(value), expiresAt);
    }

    public synchronized void attest(String keyId, String challengeId, String attestationObject) {
        validateKeyId(keyId);
        Challenge challenge = consume(challengeId, keyId, Purpose.ATTESTATION);
        if (credentials.containsKey(keyId)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "App Attest key is already registered");
        }
        if (credentials.size() >= MAX_ENTRIES) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Demo credential store is full");
        }
        PublicKey key = verifier.verifyAttestation(keyId,
                decode(attestationObject, 65_536, "attestationObject"), challenge.value());
        credentials.put(keyId, new Credential(key, 0));
    }

    public synchronized void assertKey(String keyId, String challengeId, String assertionObject,
                                       byte[] rsaPublicKey) {
        validateKeyId(keyId);
        Challenge challenge = consume(challengeId, keyId, Purpose.ASSERTION);
        Credential credential = credentials.get(keyId);
        if (credential == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "App Attest key is not registered");
        }
        long counter = verifier.verifyAssertion(credential.publicKey(), credential.counter(),
                decode(assertionObject, 65_536, "assertionObject"), challenge.value(), rsaPublicKey);
        credentials.put(keyId, new Credential(credential.publicKey(), counter));
    }

    private Challenge consume(String id, String keyId, Purpose purpose) {
        if (id == null || id.isBlank() || id.length() > 64) {
            throw badRequest("Invalid challengeId");
        }
        Challenge challenge = challenges.remove(id);
        if (challenge == null || !challenge.expiresAt().isAfter(clock.instant())
                || !challenge.keyId().equals(keyId) || challenge.purpose() != purpose) {
            throw badRequest("Challenge is expired, consumed or does not match this operation");
        }
        return challenge;
    }

    private static void validateKeyId(String keyId) {
        byte[] decoded = decode(keyId, 32, "keyId");
        if (decoded.length != 32 || !Base64.getEncoder().encodeToString(decoded).equals(keyId)) {
            throw badRequest("keyId must be canonical Base64 encoding of 32 bytes");
        }
    }

    public static byte[] decode(String value, int maxBytes, String field) {
        if (value == null || value.isBlank() || value.length() > 4 * ((maxBytes + 2) / 3)) {
            throw badRequest("Invalid Base64 " + field);
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(value);
            if (decoded.length == 0 || decoded.length > maxBytes) {
                throw badRequest("Invalid size for " + field);
            }
            return decoded;
        } catch (IllegalArgumentException e) {
            throw badRequest("Invalid Base64 " + field);
        }
    }

    private static ResponseStatusException badRequest(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }
}
