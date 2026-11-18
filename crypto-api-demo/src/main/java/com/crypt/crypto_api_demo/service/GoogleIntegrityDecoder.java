package com.crypt.crypto_api_demo.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.auth.oauth2.GoogleCredentials;
import java.io.*;
import java.net.*;
import java.util.Map;
import java.util.function.Supplier;
import java.util.function.Function;
import org.springframework.stereotype.Component;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

@Component
public class GoogleIntegrityDecoder {
    private final ObjectMapper mapper = new ObjectMapper();
    private GoogleCredentials credentials;
    private final Supplier<String> authorization;
    private final Function<String, HttpURLConnection> connections;

    public GoogleIntegrityDecoder() {
        authorization = () -> {
            try { return accessToken(); }
            catch (IOException e) { throw new IllegalStateException(); }
        };
        connections = packageName -> {
            try {
                return (HttpURLConnection) URI.create("https://playintegrity.googleapis.com/v1/"
                        + packageName + ":decodeIntegrityToken").toURL().openConnection();
            } catch (IOException e) { throw new IllegalStateException(); }
        };
    }

    GoogleIntegrityDecoder(Supplier<String> authorization, Function<String, HttpURLConnection> connections) {
        this.authorization = authorization;
        this.connections = connections;
    }

    private synchronized String accessToken() throws IOException {
        if (credentials == null) credentials = GoogleCredentials.getApplicationDefault()
                .createScoped("https://www.googleapis.com/auth/playintegrity");
        credentials.refreshIfExpired();
        return credentials.getAccessToken().getTokenValue();
    }

    public JsonNode decode(String packageName, String token) {
        HttpURLConnection connection = null;
        byte[] body = null;
        byte[] response = null;
        try {
            String accessToken = authorization.get();
            connection = connections.apply(packageName);
            connection.setConnectTimeout(10_000);
            connection.setReadTimeout(10_000);
            connection.setInstanceFollowRedirects(false);
            connection.setUseCaches(false);
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.setRequestProperty("Authorization", "Bearer " + accessToken);
            connection.setRequestProperty("Content-Type", "application/json");
            body = mapper.writeValueAsBytes(Map.of("integrity_token", token));
            connection.setFixedLengthStreamingMode(body.length);
            try (var out = connection.getOutputStream()) { out.write(body); }
            int status = connection.getResponseCode();
            if (status == 429) throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS);
            if (status >= 500) throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE);
            if (status == 401 || status == 403) throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE);
            if (status != 200) throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Integrity token rejected");
            try (var input = connection.getInputStream()) { response = input.readNBytes(65_537); }
            if (response.length > 65_536) throw new IOException();
            return mapper.readTree(response).path("tokenPayloadExternal");
        } catch (ResponseStatusException e) { throw e; }
        catch (Exception e) { throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Integrity service unavailable"); }
        finally {
            if (body != null) java.util.Arrays.fill(body, (byte) 0);
            if (response != null) java.util.Arrays.fill(response, (byte) 0);
            if (connection != null) connection.disconnect();
        }
    }
}
