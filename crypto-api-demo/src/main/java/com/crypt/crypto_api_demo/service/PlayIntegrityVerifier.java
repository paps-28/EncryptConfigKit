package com.crypt.crypto_api_demo.service;

import com.fasterxml.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.*;
import org.springframework.beans.factory.annotation.*;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class PlayIntegrityVerifier {
    private final GoogleIntegrityDecoder decoder;
    private final String packageName;
    private final Set<String> certificates;
    private final Clock clock;
    private final int requestsPerMinute;
    private long window;
    private int requests;

    @Autowired
    public PlayIntegrityVerifier(GoogleIntegrityDecoder decoder,
            @Value("${play-integrity.package-name:}") String packageName,
            @Value("${play-integrity.certificate-sha256:}") String certificates,
            @Value("${play-integrity.requests-per-minute:60}") int requestsPerMinute) {
        this(decoder, packageName, certificates, requestsPerMinute, Clock.systemUTC());
    }

    public PlayIntegrityVerifier(GoogleIntegrityDecoder decoder, String packageName, String certificates,
                                 int requestsPerMinute, Clock clock) {
        this.decoder = decoder;
        this.packageName = packageName;
        this.certificates = new HashSet<>();
        for (String value : certificates.split(",")) if (!value.isBlank()) this.certificates.add(value.trim());
        this.requestsPerMinute = requestsPerMinute;
        this.clock = clock;
    }

    public void requireConfigured() {
        if (!packageName.matches("[a-zA-Z][a-zA-Z0-9_]*(\\.[a-zA-Z][a-zA-Z0-9_]*)+")
                || certificates.isEmpty() || requestsPerMinute <= 0)
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Integrity is not configured");
        for (String cert : certificates) {
            try { if (Base64.getUrlDecoder().decode(cert).length != 32) throw new IllegalArgumentException(); }
            catch (IllegalArgumentException e) { throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Invalid certificate configuration"); }
        }
    }

    private synchronized void rateLimit() {
        long minute = clock.millis() / 60_000;
        if (minute != window) { window = minute; requests = 0; }
        if (requests >= requestsPerMinute) throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS);
        requests++;
    }

    public void verify(String token, byte[] challenge, byte[] der) {
        requireConfigured();
        rateLimit();
        JsonNode payload = decoder.decode(packageName, token);
        JsonNode request = payload.path("requestDetails");
        JsonNode app = payload.path("appIntegrity");
        long timestamp;
        try { timestamp = Long.parseLong(request.path("timestampMillis").asText()); }
        catch (Exception e) { throw rejected(); }
        long now = clock.millis();
        if (timestamp < now - 300_000 || timestamp > now + 30_000
                || !packageName.equals(request.path("requestPackageName").asText())
                || !MessageDigest.isEqual(requestHash(challenge, der).getBytes(StandardCharsets.US_ASCII),
                    request.path("requestHash").asText().getBytes(StandardCharsets.US_ASCII))
                || !"PLAY_RECOGNIZED".equals(app.path("appRecognitionVerdict").asText())
                || !packageName.equals(app.path("packageName").asText())
                || !containsAllowedCertificate(app.path("certificateSha256Digest"))
                || !contains(payload.path("deviceIntegrity").path("deviceRecognitionVerdict"), "MEETS_DEVICE_INTEGRITY")
                || !"LICENSED".equals(payload.path("accountDetails").path("appLicensingVerdict").asText()))
            throw rejected();
    }

    private boolean containsAllowedCertificate(JsonNode values) {
        if (!values.isArray() || values.isEmpty()) return false;
        for (JsonNode value : values) if (!certificates.contains(value.asText())) return false;
        return true;
    }

    private static boolean contains(JsonNode values, String expected) {
        for (JsonNode value : values) if (expected.equals(value.asText())) return true;
        return false;
    }

    public static String requestHash(byte[] challenge, byte[] der) {
        try {
            MessageDigest hash = MessageDigest.getInstance("SHA-256");
            hash.update("EncryptConfigKit.AppAttest.AESKey.v1".getBytes(StandardCharsets.UTF_8));
            hash.update((byte) 0);
            hash.update(challenge);
            return Base64.getEncoder().encodeToString(hash.digest(der));
        } catch (Exception e) { throw new IllegalStateException(e); }
    }

    private static ResponseStatusException rejected() {
        return new ResponseStatusException(HttpStatus.FORBIDDEN, "Integrity rejected");
    }
}
