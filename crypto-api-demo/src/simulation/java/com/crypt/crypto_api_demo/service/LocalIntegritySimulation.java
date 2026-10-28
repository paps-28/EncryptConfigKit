package com.crypt.crypto_api_demo.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;

@RestController
@Primary
@Profile("local-simulation")
public class LocalIntegritySimulation extends GoogleIntegrityDecoder {
    private final AtomicLong challenges = new AtomicLong();
    private final AtomicLong deliveries = new AtomicLong();
    private final AtomicLong decoded = new AtomicLong();

    public LocalIntegritySimulation(@Value("${server.address:}") String address, @Value("${server.port:0}") int port) {
        if (!"127.0.0.1".equals(address) || port != 18080) throw new IllegalStateException("Simulation requires loopback port 18080");
    }

    @Override public JsonNode decode(String packageName, String token) {
        String prefix = "local-simulation-v1.";
        if (!token.startsWith(prefix)) throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        String hash = token.substring(prefix.length());
        try {
            if (Base64.getDecoder().decode(hash).length != 32) throw new IllegalArgumentException();
        } catch (Exception e) { throw new ResponseStatusException(HttpStatus.FORBIDDEN); }
        var payload = new ObjectMapper().createObjectNode();
        payload.putObject("requestDetails").put("requestPackageName", packageName).put("requestHash", hash)
                .put("timestampMillis", Long.toString(System.currentTimeMillis()));
        payload.putObject("appIntegrity").put("packageName", packageName).put("appRecognitionVerdict", "PLAY_RECOGNIZED")
                .putArray("certificateSha256Digest").add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        payload.putObject("deviceIntegrity").putArray("deviceRecognitionVerdict").add("MEETS_DEVICE_INTEGRITY");
        payload.putObject("accountDetails").put("appLicensingVerdict", "LICENSED");
        decoded.incrementAndGet();
        return payload;
    }

    @GetMapping("/local-simulation/status")
    public Map<String, Object> status() {
        return Map.of("simulated", true, "challenges", challenges.get(), "deliveries", deliveries.get(), "googleDecodeSimulations", decoded.get());
    }

    @Bean public OncePerRequestFilter simulationTraffic() {
        return new OncePerRequestFilter() {
            @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                    throws ServletException, IOException {
                response.setHeader("X-Integrity-Simulation", "true");
                chain.doFilter(request, response);
                if (response.getStatus() == 200 && "POST".equals(request.getMethod())) {
                    if (request.getRequestURI().equals("/api/crypto/play-integrity/challenge")) challenges.incrementAndGet();
                    if (request.getRequestURI().equals("/api/crypto/play-integrity/public-key")) deliveries.incrementAndGet();
                }
            }
        };
    }
}
