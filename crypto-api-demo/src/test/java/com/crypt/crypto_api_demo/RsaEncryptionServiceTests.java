package com.crypt.crypto_api_demo;

import com.crypt.crypto_api_demo.service.RsaEncryptionService;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.Base64;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class RsaEncryptionServiceTests {
    private static final KeyPair KEY = generateKeyPair();

    @ParameterizedTest(name = "{0}")
    @MethodSource("publicKeyFormats")
    void parsesExactDerAndBothEncryptOverloadsRoundTrip(String format, String publicKey, KeyPair key)
            throws Exception {
        var service = new RsaEncryptionService();
        var parsed = service.parsePublicKey(publicKey);
        var expected = (RSAPublicKey) key.getPublic();
        assertArrayEquals(expected.getEncoded(), parsed.der());
        assertEquals(expected.getModulus(), parsed.key().getModulus());
        assertEquals(expected.getPublicExponent(), parsed.key().getPublicExponent());

        String plaintext = "test-aes-key-base64-ñ";
        assertEquals(plaintext, decrypt(service.encrypt(plaintext, publicKey), key.getPrivate()));
        assertEquals(plaintext, decrypt(service.encrypt(plaintext, parsed.key()), key.getPrivate()));
    }

    static Stream<Arguments> publicKeyFormats() {
        String base64 = Base64.getEncoder().encodeToString(KEY.getPublic().getEncoded());
        return Stream.of(
                Arguments.of("Base64", base64, KEY),
                Arguments.of("Base64 LF", wrap(base64, "\n"), KEY),
                Arguments.of("Base64 CRLF", wrap(base64, "\r\n"), KEY),
                Arguments.of("Base64 spaces", " \t" + wrap(base64, " \t ") + "  ", KEY),
                Arguments.of("PEM LF", pem(wrap(base64, "\n"), "\n"), KEY),
                Arguments.of("PEM CRLF", pem(wrap(base64, "\r\n"), "\r\n"), KEY),
                Arguments.of("PEM spaces", " \t" + pem(wrap(base64, " \t\n "), " \r\n ") + "  ", KEY));
    }

    static String decrypt(String ciphertext, PrivateKey key) throws Exception {
        Cipher decryptor = Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding");
        decryptor.init(Cipher.DECRYPT_MODE, key, new OAEPParameterSpec(
                "SHA-512", "MGF1", MGF1ParameterSpec.SHA512, PSource.PSpecified.DEFAULT));
        return new String(decryptor.doFinal(Base64.getDecoder().decode(ciphertext)), StandardCharsets.UTF_8);
    }

    private static String wrap(String base64, String separator) {
        return String.join(separator, base64.split("(?<=\\G.{64})"));
    }

    private static String pem(String body, String newline) {
        return "-----BEGIN PUBLIC KEY-----" + newline + body + newline + "-----END PUBLIC KEY-----";
    }

    private static KeyPair generateKeyPair() {
        try {
            var generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }
}
