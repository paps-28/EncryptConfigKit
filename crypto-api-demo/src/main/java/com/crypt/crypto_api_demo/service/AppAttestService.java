package com.crypt.crypto_api_demo.service;

import java.security.PublicKey;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AppAttestService {
    private static final Logger log = LoggerFactory.getLogger(AppAttestService.class);
    public enum Purpose { ATTESTATION, ASSERTION }
    public record ChallengeResponse(String challengeId, String challenge, Instant expiresAt) {}
    private record Credential(PublicKey publicKey, long counter) {}

    private static final int MAX_ENTRIES = 10_000;
    private final ChallengeService challenges;
    private final Map<String, Credential> credentials = new HashMap<>();
    private final AppAttestVerifier verifier;

    @Autowired
    public AppAttestService(AppAttestVerifier verifier, ChallengeService challenges) {
        this.verifier = verifier;
        this.challenges = challenges;
    }

    public AppAttestService(AppAttestVerifier verifier) {
        this(verifier, new ChallengeService());
    }

    AppAttestService(AppAttestVerifier verifier, Clock clock) {
        this(verifier, new ChallengeService(clock));
    }

    // In-memory demo storage: synchronization makes challenge consumption and counters atomic.
    public synchronized ChallengeResponse challenge(String keyId, Purpose purpose) {
        log.debug("App Attest challenge stage=validation purpose={}", purpose);
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
        var response = challenges.issue(operation(purpose), keyId);
        return new ChallengeResponse(response.challengeId(), response.challenge(), response.expiresAt());
    }

    public synchronized void attest(String keyId, String challengeId, String attestationObject) {
        log.debug("App Attest register stage=validation");
        validateKeyId(keyId);
        byte[] challenge = challenges.consume(challengeId, operation(Purpose.ATTESTATION), keyId);
        if (credentials.containsKey(keyId)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "App Attest key is already registered");
        }
        if (credentials.size() >= MAX_ENTRIES) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Demo credential store is full");
        }
        log.debug("App Attest register stage=cryptographic-verification");
        PublicKey key = verifier.verifyAttestation(keyId,
                decode(attestationObject, 65_536, "attestationObject"), challenge);
        credentials.put(keyId, new Credential(key, 0));
        log.debug("App Attest register stage=stored counter=0");
    }

    public synchronized void assertKey(String keyId, String challengeId, String assertionObject,
                                       byte[] rsaPublicKey) {
        log.info("App Attest assertion start");
        log.debug("App Attest assertion stage=validation");
        validateKeyId(keyId);
        byte[] challenge = challenges.consume(challengeId, operation(Purpose.ASSERTION), keyId);
        Credential credential = credentials.get(keyId);
        if (credential == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "App Attest key is not registered");
        }
        log.debug("App Attest assertion stage=cryptographic-verification previousCounter={}", credential.counter());
        long counter = verifier.verifyAssertion(credential.publicKey(), credential.counter(),
                decode(assertionObject, 65_536, "assertionObject"), challenge, rsaPublicKey);
        credentials.put(keyId, new Credential(credential.publicKey(), counter));
        log.debug("App Attest assertion stage=stored counter={}", counter);
        log.info("App Attest assertion success");
    }

    private static ChallengeService.Operation operation(Purpose purpose) {
        return purpose == Purpose.ATTESTATION ? ChallengeService.Operation.APPLE_ATTESTATION
                : ChallengeService.Operation.APPLE_ASSERTION;
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
