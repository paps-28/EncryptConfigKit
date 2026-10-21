package com.crypt.crypto_api_demo;

import com.crypt.crypto_api_demo.service.AppAttestVerifier;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.web.server.ResponseStatusException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AppAttestVerifierTests {
    private static final String APP_ID = "TEAM.com.example.app";
    private static final byte[] DOMAIN = utf8("EncryptConfigKit.AppAttest.AESKey.v1");
    private static final byte[] CHALLENGE = {0, 1, 2, (byte) 0xff, 4, 5};
    private static final ObjectMapper CBOR = new ObjectMapper(new CBORFactory());
    private static KeyPair rootKey, appKey, otherKey;
    private static X509Certificate root;
    private static byte[] rsaPublicKey, keyId, production, development, validAssertion;
    private static AppAttestVerifier verifier;

    @BeforeAll
    static void fixtures() throws Exception {
        rootKey = ecKey();
        appKey = ecKey();
        otherKey = ecKey();
        root = certificate(rootKey.getPublic(), rootKey.getPrivate(), true, null);
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        rsaPublicKey = rsa.generateKeyPair().getPublic().getEncoded();
        keyId = hash(point(appKey.getPublic()));
        production = attestation("production", CHALLENGE, false);
        development = attestation("development", CHALLENGE, false);
        verifier = verifier(APP_ID, "production", root);
        validAssertion = assertion(1, clientDataHash(), appKey.getPrivate());
    }

    @ParameterizedTest
    @ValueSource(strings = {"production", "development"})
    void acceptsAttestationForConfiguredEnvironment(String environment) throws Exception {
        byte[] object = "production".equals(environment) ? production : development;
        PublicKey verified = verifier(APP_ID, environment, root)
                .verifyAttestation(keyIdString(), object, CHALLENGE);
        assertArrayEquals(appKey.getPublic().getEncoded(), verified.getEncoded());
    }

    @Test
    void rejectsWrongNonce() throws Exception {
        byte[] wrongNonce = attestation("production", changed(CHALLENGE), false);
        status(403, () -> verifier.verifyAttestation(keyIdString(), wrongNonce, CHALLENGE));
    }

    @Test
    void rejectsUntrustedRoot() throws Exception {
        X509Certificate unrelatedRoot = certificate(otherKey.getPublic(), otherKey.getPrivate(), true, null);
        status(403, () -> verifier(APP_ID, "production", unrelatedRoot)
                .verifyAttestation(keyIdString(), production, CHALLENGE));
    }

    @Test
    void rejectsWrongAppIdEnvironmentAndKeyId() {
        assertAll(
                () -> status(403, () -> verifier("TEAM.other.app", "production", root)
                        .verifyAttestation(keyIdString(), production, CHALLENGE)),
                () -> status(403, () -> verifier.verifyAttestation(keyIdString(), development, CHALLENGE)),
                () -> status(403, () -> verifier(APP_ID, "development", root)
                        .verifyAttestation(keyIdString(), production, CHALLENGE)),
                () -> status(403, () -> verifier.verifyAttestation(
                        Base64.getEncoder().encodeToString(changed(keyId)), production, CHALLENGE)));
    }

    @Test
    void rejectsCoseKeyThatDoesNotMatchCertificate() throws Exception {
        // The certificate nonce covers this altered COSE key, isolating the key-match check.
        byte[] mismatched = attestation("production", CHALLENGE, true);
        status(403, () -> verifier.verifyAttestation(keyIdString(), mismatched, CHALLENGE));
    }

    @Test
    void acceptsAssertionOverExactSwiftDomainPayload() {
        assertEquals(1, verifier.verifyAssertion(appKey.getPublic(), 0,
                validAssertion, CHALLENGE, rsaPublicKey));
    }

    @Test
    void bindsAssertionToRawRsaKeyAndChallenge() {
        assertAll(
                () -> status(403, () -> verifier.verifyAssertion(appKey.getPublic(), 0,
                        validAssertion, CHALLENGE, changed(rsaPublicKey))),
                () -> status(403, () -> verifier.verifyAssertion(appKey.getPublic(), 0,
                        validAssertion, changed(CHALLENGE), rsaPublicKey)));
    }

    @Test
    void enforcesMonotonicUnsignedCounter() throws Exception {
        assertAll(
                () -> status(403, () -> verifier.verifyAssertion(appKey.getPublic(), 1,
                        validAssertion, CHALLENGE, rsaPublicKey)),
                () -> status(403, () -> verifier.verifyAssertion(appKey.getPublic(), 2,
                        validAssertion, CHALLENGE, rsaPublicKey)),
                () -> status(403, () -> verifier.verifyAssertion(appKey.getPublic(), 0xffff_ffffL,
                        validAssertion, CHALLENGE, rsaPublicKey)));
        assertEquals(0xffff_ffffL, verifier.verifyAssertion(appKey.getPublic(), 1,
                assertion(0xffff_ffffL, clientDataHash(), appKey.getPrivate()), CHALLENGE, rsaPublicKey));
    }

    @Test
    void rejectsCounterTamperingAndIncorrectSignature() throws Exception {
        var altered = CBOR.readTree(validAssertion);
        byte[] authData = altered.get("authenticatorData").binaryValue();
        authData[36] = 2;
        byte[] tampered = CBOR.writeValueAsBytes(Map.of("authenticatorData", authData,
                "signature", altered.get("signature").binaryValue()));
        byte[] wrongSignature = assertion(1, clientDataHash(), otherKey.getPrivate());
        assertAll(
                () -> status(403, () -> verifier.verifyAssertion(appKey.getPublic(), 0,
                        tampered, CHALLENGE, rsaPublicKey)),
                () -> status(403, () -> verifier.verifyAssertion(appKey.getPublic(), 0,
                        wrongSignature, CHALLENGE, rsaPublicKey)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"wrong-domain", "missing-separator", "double-hash"})
    void rejectsIncorrectSwiftPayloadHash(String mistake) throws Exception {
        byte[] incorrect = switch (mistake) {
            case "wrong-domain" -> hash(utf8("EncryptConfigKit.AppAttest.AESKey.v2"),
                    new byte[]{0}, CHALLENGE, rsaPublicKey);
            case "missing-separator" -> hash(DOMAIN, CHALLENGE, rsaPublicKey);
            default -> hash(clientDataHash());
        };
        byte[] object = assertion(1, incorrect, appKey.getPrivate());
        status(403, () -> verifier.verifyAssertion(appKey.getPublic(), 0, object, CHALLENGE, rsaPublicKey));
    }

    @Test
    void rejectsMalformedCborForBothApis() throws Exception {
        ByteArrayOutputStream duplicate = new ByteArrayOutputStream();
        try (CBORGenerator generator = new CBORFactory().createGenerator(duplicate)) {
            generator.writeStartObject();
            generator.writeBinaryField("signature", new byte[]{1});
            generator.writeBinaryField("signature", new byte[]{2});
            generator.writeEndObject();
        }
        for (byte[] malformed : List.of(new byte[0], new byte[]{(byte) 0xff},
                new byte[65_537], duplicate.toByteArray(),
                Arrays.copyOf(validAssertion, validAssertion.length - 1),
                concat(validAssertion, new byte[]{0}), concat(new byte[]{(byte) 0xc0}, validAssertion))) {
            assertAll(
                    () -> status(400, () -> verifier.verifyAssertion(appKey.getPublic(), 0,
                            malformed, CHALLENGE, rsaPublicKey)),
                    () -> status(400, () -> verifier.verifyAttestation(keyIdString(), malformed, CHALLENGE)));
        }
        status(400, () -> verifier.verifyAttestation(keyIdString(), concat(production, new byte[]{0}), CHALLENGE));
    }

    @ParameterizedTest
    @ValueSource(ints = {0x40, 0x80})
    void rejectsUnsupportedAssertionFlags(int flags) throws Exception {
        byte[] authData = assertionHeader(1);
        authData[32] = (byte) flags;
        byte[] object = CBOR.writeValueAsBytes(Map.of("authenticatorData", authData,
                "signature", CBOR.readTree(validAssertion).get("signature").binaryValue()));
        status(400, () -> verifier.verifyAssertion(appKey.getPublic(), 0, object, CHALLENGE, rsaPublicKey));
    }

    private static AppAttestVerifier verifier(String appId, String environment, X509Certificate anchor)
            throws Exception {
        byte[] encoded = anchor.getEncoded();
        return new AppAttestVerifier(appId, environment, "memory:root", new DefaultResourceLoader() {
            @Override
            public Resource getResource(String location) {
                assertEquals("memory:root", location);
                return new ByteArrayResource(encoded);
            }
        });
    }

    private static byte[] attestation(String environment, byte[] nonceChallenge, boolean wrongCose)
            throws Exception {
        byte[] header = new byte[87];
        System.arraycopy(hash(utf8(APP_ID)), 0, header, 0, 32);
        header[32] = 0x40;
        byte[] aaguid = Arrays.copyOf(utf8("development".equals(environment)
                ? "appattestdevelop" : "appattest"), 16);
        System.arraycopy(aaguid, 0, header, 37, 16);
        header[54] = 32;
        System.arraycopy(keyId, 0, header, 55, 32);
        byte[] authData = concat(header, cose(wrongCose ? otherKey.getPublic() : appKey.getPublic()));
        byte[] nonce = hash(authData, hash(nonceChallenge));
        X509Certificate leaf = certificate(appKey.getPublic(), rootKey.getPrivate(), false, nonce);
        return CBOR.writeValueAsBytes(Map.of("fmt", "apple-appattest", "authData", authData,
                "attStmt", Map.of("x5c", List.of(leaf.getEncoded(), root.getEncoded()))));
    }

    private static byte[] cose(PublicKey key) throws Exception {
        byte[] point = point(key);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (CBORGenerator generator = new CBORFactory().createGenerator(out)) {
            generator.writeStartObject();
            generator.writeFieldId(1); generator.writeNumber(2);
            generator.writeFieldId(3); generator.writeNumber(-7);
            generator.writeFieldId(-1); generator.writeNumber(1);
            generator.writeFieldId(-2); generator.writeBinary(Arrays.copyOfRange(point, 1, 33));
            generator.writeFieldId(-3); generator.writeBinary(Arrays.copyOfRange(point, 33, 65));
            generator.writeEndObject();
        }
        return out.toByteArray();
    }

    private static byte[] clientDataHash() throws Exception {
        // Mirrors AppAttestPayload.make in Swift: no lengths, encoding, or extra hash layers.
        return hash(DOMAIN, new byte[]{0}, CHALLENGE, rsaPublicKey);
    }

    private static byte[] assertion(long counter, byte[] clientHash, PrivateKey signer) throws Exception {
        byte[] authData = assertionHeader(counter);
        // Sign Apple's already-hashed nonce directly, independently of SHA256withECDSA in main.
        byte[] signature = sign("NONEwithECDSA", signer, hash(authData, clientHash));
        return CBOR.writeValueAsBytes(Map.of("authenticatorData", authData, "signature", signature));
    }

    private static byte[] assertionHeader(long counter) throws Exception {
        return ByteBuffer.allocate(37).put(hash(utf8(APP_ID))).put((byte) 0).putInt((int) counter).array();
    }

    private static X509Certificate certificate(PublicKey subject, PrivateKey signer, boolean ca, byte[] nonce)
            throws Exception {
        AlgorithmIdentifier algorithm = new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256);
        V3TBSCertificateGenerator builder = new V3TBSCertificateGenerator();
        builder.setSerialNumber(new ASN1Integer(ca ? BigInteger.ONE : BigInteger.TWO));
        builder.setSignature(algorithm);
        builder.setIssuer(new X500Name("CN=Synthetic App Attest Root"));
        builder.setSubject(new X500Name(ca ? "CN=Synthetic App Attest Root" : "CN=Synthetic App Attest Key"));
        Instant now = Instant.now();
        builder.setStartDate(new Time(Date.from(now.minus(1, ChronoUnit.DAYS))));
        builder.setEndDate(new Time(Date.from(now.plus(7, ChronoUnit.DAYS))));
        builder.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(subject.getEncoded()));
        ExtensionsGenerator extensions = new ExtensionsGenerator();
        extensions.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        extensions.addExtension(Extension.keyUsage, true, new KeyUsage(ca
                ? KeyUsage.keyCertSign | KeyUsage.cRLSign : KeyUsage.digitalSignature));
        if (nonce != null) {
            extensions.addExtension(new ASN1ObjectIdentifier("1.2.840.113635.100.8.2"), false,
                    new DERSequence(new DERTaggedObject(true, 1, new DEROctetString(nonce))));
        }
        builder.setExtensions(extensions.generate());
        TBSCertificate tbs = builder.generateTBSCertificate();
        byte[] signature = sign("SHA256withECDSA", signer, tbs.getEncoded("DER"));
        byte[] encoded = new DERSequence(new ASN1Encodable[]{tbs, algorithm, new DERBitString(signature)})
                .getEncoded("DER");
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(encoded));
    }

    private static KeyPair ecKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private static byte[] point(PublicKey key) {
        ECPublicKey ec = (ECPublicKey) key;
        byte[] point = new byte[65];
        point[0] = 4;
        BigInteger[] coordinates = {ec.getW().getAffineX(), ec.getW().getAffineY()};
        for (int i = 0; i < coordinates.length; i++) {
            byte[] bytes = coordinates[i].toByteArray();
            int length = Math.min(32, bytes.length);
            System.arraycopy(bytes, bytes.length - length, point, 1 + i * 32 + 32 - length, length);
        }
        return point;
    }

    private static byte[] sign(String algorithm, PrivateKey key, byte[] message) throws Exception {
        Signature signature = Signature.getInstance(algorithm);
        signature.initSign(key);
        signature.update(message);
        return signature.sign();
    }

    private static byte[] hash(byte[]... parts) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(concat(parts));
    }

    private static byte[] concat(byte[]... parts) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) out.write(part);
        return out.toByteArray();
    }

    private static byte[] changed(byte[] bytes) {
        byte[] copy = bytes.clone();
        copy[copy.length - 1] ^= 1;
        return copy;
    }

    private static byte[] utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static String keyIdString() {
        return Base64.getEncoder().encodeToString(keyId);
    }

    private static void status(int expected, Executable action) {
        assertEquals(expected, assertThrows(ResponseStatusException.class, action).getStatusCode().value());
    }
}
