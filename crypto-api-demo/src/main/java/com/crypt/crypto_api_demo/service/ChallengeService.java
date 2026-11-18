package com.crypt.crypto_api_demo.service;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

@Service
public class ChallengeService {
    public enum Operation { APPLE_ATTESTATION, APPLE_ASSERTION, PLAY_INTEGRITY }
    public record Response(String challengeId, String challenge, Instant expiresAt) {}
    private record Entry(Operation operation, String keyId, byte[] value, Instant expiresAt) {}
    private final Map<String, Entry> entries = new HashMap<>();
    private final SecureRandom random = new SecureRandom();
    private final Clock clock;

    public ChallengeService() { this(Clock.systemUTC()); }
    public ChallengeService(Clock clock) { this.clock = clock; }

    public synchronized Response issue(Operation operation, String keyId) {
        Objects.requireNonNull(operation);
        Instant now = clock.instant();
        entries.values().removeIf(entry -> !entry.expiresAt().isAfter(now));
        if (entries.size() >= 10_000) throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS);
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        String id = UUID.randomUUID().toString();
        Instant expires = now.plusSeconds(300);
        entries.put(id, new Entry(operation, keyId, bytes, expires));
        return new Response(id, Base64.getEncoder().encodeToString(bytes), expires);
    }

    public synchronized byte[] consume(String id, Operation operation, String keyId) {
        if (id == null || id.isBlank() || id.length() > 64)
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid challengeId");
        Entry entry = entries.remove(id);
        if (entry == null || !entry.expiresAt().isAfter(clock.instant()) || entry.operation() != operation
                || !Objects.equals(entry.keyId(), keyId))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or consumed challenge");
        return entry.value();
    }
}
