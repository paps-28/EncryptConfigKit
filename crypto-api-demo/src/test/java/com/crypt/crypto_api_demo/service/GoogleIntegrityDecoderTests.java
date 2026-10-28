package com.crypt.crypto_api_demo.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import static org.junit.jupiter.api.Assertions.*;

class GoogleIntegrityDecoderTests {
    static class Connection extends HttpURLConnection {
        int status = 200;
        byte[] response = "{\"tokenPayloadExternal\":{\"requestDetails\":{}}}".getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        boolean disconnected;
        int calls;
        Connection() throws Exception { super(URI.create("https://playintegrity.googleapis.com/v1/test.application:decodeIntegrityToken").toURL()); }
        @Override public void connect() {}
        @Override public boolean usingProxy() { return false; }
        @Override public void disconnect() { disconnected = true; }
        @Override public OutputStream getOutputStream() { return body; }
        @Override public int getResponseCode() { calls++; return status; }
        @Override public InputStream getInputStream() { return new ByteArrayInputStream(response); }
    }

    @Test void realClientBuildsBoundedAuthenticatedRequestWithoutRetry() throws Exception {
        var connection = new Connection();
        var decoder = new GoogleIntegrityDecoder(() -> "test-credential", name -> {
            assertEquals("test.application", name);
            return connection;
        });
        assertTrue(decoder.decode("test.application", "test-only-token").has("requestDetails"));
        assertEquals("POST", connection.getRequestMethod());
        assertEquals("Bearer test-credential", connection.getRequestProperty("Authorization"));
        var json = new ObjectMapper().readTree(connection.body.toByteArray());
        assertEquals(1, json.size());
        assertEquals("test-only-token", json.get("integrity_token").asText());
        assertEquals(10000, connection.getConnectTimeout());
        assertEquals(10000, connection.getReadTimeout());
        assertFalse(connection.getInstanceFollowRedirects());
        assertFalse(connection.getUseCaches());
        assertTrue(connection.disconnected);
        assertEquals(1, connection.calls);
    }

    @Test void rejectedTransientAndOversizeResponsesNeverExposePayload() throws Exception {
        for (int status : new int[]{400, 401, 403, 429, 500, 302, 200}) {
            var connection = new Connection(); connection.status = status;
            connection.response = "sensitive-test-material".repeat(4000).getBytes(StandardCharsets.UTF_8);
            var decoder = new GoogleIntegrityDecoder(() -> "test-credential", name -> connection);
            var error = assertThrows(ResponseStatusException.class, () -> decoder.decode("test.application", "test-only-token"));
            int expected = status == 429 ? 429 : (status == 400 || status == 302 ? 403 : 503);
            assertEquals(expected, error.getStatusCode().value());
            assertFalse(error.toString().contains("sensitive-test-material"));
            assertTrue(connection.disconnected);
            assertEquals(1, connection.calls);
        }
    }

    @Test void missingCredentialsFailBeforeHttp() {
        var decoder = new GoogleIntegrityDecoder(() -> { throw new IllegalStateException(); }, name -> { fail("HTTP without credentials"); return null; });
        assertEquals(503, assertThrows(ResponseStatusException.class, () -> decoder.decode("test.application", "test-only-token")).getStatusCode().value());
    }
}
