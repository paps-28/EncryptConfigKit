package com.crypt.crypto_api_demo.service;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORParser;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Set;

@Service
public class AppAttestVerifier {

    private static final int MAX_CBOR_BYTES = 65_536;
    private static final int MAX_CHALLENGE_BYTES = 4_096;
    private static final int MAX_RSA_KEY_BYTES = 16_384;
    private static final int AUTHENTICATOR_HEADER_BYTES = 37;
    private static final int FLAG_AT = 0x40;
    private static final int FLAG_ED = 0x80;
    private static final long MAX_COUNTER = 0xffff_ffffL;
    private static final String NONCE_OID = "1.2.840.113635.100.8.2";
    private static final byte[] ASSERTION_DOMAIN =
            "EncryptConfigKit.AppAttest.AESKey.v1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] DEVELOPMENT_AAGUID =
            "appattestdevelop".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] PRODUCTION_AAGUID = Arrays.copyOf(
            "appattest".getBytes(StandardCharsets.US_ASCII), 16);

    private final String appId;
    private final String environment;
    private final String rootLocation;
    private final ResourceLoader resourceLoader;
    private final ObjectMapper cbor;
    private volatile X509Certificate rootCertificate;

    public AppAttestVerifier(
            @Value("${app-attest.app-id:}") String appId,
            @Value("${app-attest.environment:production}") String environment,
            @Value("${app-attest.root-certificate:classpath:apple-app-attest-root.pem}") String rootLocation,
            ResourceLoader resourceLoader) {
        this.appId = appId;
        this.environment = environment;
        this.rootLocation = rootLocation;
        this.resourceLoader = resourceLoader;
        CBORFactory factory = new CBORFactory();
        factory.setStreamReadConstraints(StreamReadConstraints.builder()
                .maxNestingDepth(8)
                .maxStringLength(MAX_CBOR_BYTES)
                .maxNameLength(128)
                .maxNumberLength(32)
                .build());
        factory.enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
        this.cbor = new ObjectMapper(factory);
    }

    public PublicKey verifyAttestation(String keyId, byte[] attestationObject, byte[] challenge) {
        checkConfiguration();
        X509Certificate root = rootCertificate();
        requireBytes(challenge, MAX_CHALLENGE_BYTES, "Invalid challenge");
        byte[] decodedKeyId = decodeKeyId(keyId);
        JsonNode object = readCbor(attestationObject);
        requireFields(object, Set.of("fmt", "attStmt", "authData"));
        JsonNode format = object.get("fmt");
        if (format == null || !format.isTextual()) {
            throw malformed("Missing attestation format");
        }
        if (!"apple-appattest".equals(format.textValue())) {
            throw invalid("Unsupported attestation format");
        }
        JsonNode statement = object.get("attStmt");
        requireFields(statement, Set.of("x5c", "receipt"));
        if (statement.has("receipt")) {
            binary(statement.get("receipt"), MAX_CBOR_BYTES, "Invalid receipt");
        }
        List<X509Certificate> certificates = certificates(statement.get("x5c"));
        X509Certificate leaf = certificates.getFirst();
        validateChain(certificates, root);
        ECPublicKey publicKey = p256Key(leaf.getPublicKey());
        byte[] authData = binary(object.get("authData"), MAX_CBOR_BYTES, "Invalid authenticator data");
        // Header + AAGUID + credential length + the required 32-byte credential ID.
        if (authData.length <= AUTHENTICATOR_HEADER_BYTES + 16 + 2 + 32) {
            throw malformed("Truncated attested credential data");
        }
        checkHeader(authData, true);
        if (counter(authData) != 0) {
            throw invalid("Attestation counter must be zero");
        }
        byte[] expectedAaguid = "development".equals(environment)
                ? DEVELOPMENT_AAGUID : PRODUCTION_AAGUID;
        if (!MessageDigest.isEqual(expectedAaguid, Arrays.copyOfRange(authData, 37, 53))) {
            throw invalid("Attestation environment does not match");
        }
        int credentialLength = ((authData[53] & 0xff) << 8) | (authData[54] & 0xff);
        if (credentialLength != 32) {
            throw invalid("Invalid credential ID length");
        }
        byte[] credentialId = Arrays.copyOfRange(authData, 55, 87);
        byte[] rawPoint = uncompressedPoint(publicKey);
        if (!MessageDigest.isEqual(decodedKeyId, sha256(rawPoint))
                || !MessageDigest.isEqual(decodedKeyId, credentialId)) {
            throw invalid("Attestation key ID does not match");
        }
        // The remaining bytes must contain exactly one COSE key: no extensions or trailing data.
        validateCoseKey(readCbor(Arrays.copyOfRange(authData, 87, authData.length), true), rawPoint);
        verifyNonce(leaf, sha256(authData, sha256(challenge)));
        return publicKey;
    }

    /** The caller must atomically persist the returned counter and consume the challenge once. */
    public long verifyAssertion(PublicKey key, long previousCounter, byte[] assertionObject,
                                byte[] challenge, byte[] rsaPublicKey) {
        checkConfiguration();
        requireBytes(challenge, MAX_CHALLENGE_BYTES, "Invalid challenge");
        requireBytes(rsaPublicKey, MAX_RSA_KEY_BYTES, "Invalid RSA public key bytes");
        if (previousCounter < 0 || previousCounter > MAX_COUNTER) {
            throw malformed("Previous counter is not uint32");
        }
        ECPublicKey publicKey = p256Key(key);
        JsonNode object = readCbor(assertionObject);
        requireFields(object, Set.of("signature", "authenticatorData"));
        byte[] authData = binary(object.get("authenticatorData"), AUTHENTICATOR_HEADER_BYTES,
                "Invalid authenticator data");
        if (authData.length != AUTHENTICATOR_HEADER_BYTES) {
            throw malformed("Assertion authenticator data must be 37 bytes");
        }
        checkHeader(authData, false);
        long nextCounter = counter(authData);
        if (nextCounter <= previousCounter) {
            throw invalid("Assertion counter did not increase");
        }
        byte[] signature = binary(object.get("signature"), 72, "Invalid assertion signature");
        validateEcdsaEncoding(signature, publicKey.getParams().getOrder());
        byte[] clientDataHash = sha256(ASSERTION_DOMAIN, new byte[]{0}, challenge, rsaPublicKey);
        try {
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(publicKey);
            // Apple signs nonce = SHA256(authData || clientDataHash). The JCA algorithm
            // performs that hash; hashing clientDataHash again would verify the wrong message.
            verifier.update(authData);
            verifier.update(clientDataHash);
            if (!verifier.verify(signature)) {
                throw invalid("Invalid assertion signature");
            }
            return nextCounter;
        } catch (GeneralSecurityException e) {
            throw invalid("Invalid assertion signature");
        }
    }

    private void checkConfiguration() {
        if (appId == null || appId.isBlank() || rootLocation == null || rootLocation.isBlank()
                || !("production".equals(environment) || "development".equals(environment))) {
            throw unavailable("App Attest configuration is missing or invalid");
        }
    }

    private X509Certificate rootCertificate() {
        X509Certificate loaded = rootCertificate;
        if (loaded == null) {
            synchronized (this) {
                loaded = rootCertificate;
                if (loaded == null) {
                    try (InputStream input = resourceLoader.getResource(rootLocation).getInputStream()) {
                        byte[] encoded = input.readNBytes(MAX_CBOR_BYTES + 1);
                        if (encoded.length > MAX_CBOR_BYTES) {
                            throw unavailable("App Attest root certificate is too large");
                        }
                        ByteArrayInputStream source = new ByteArrayInputStream(encoded);
                        loaded = (X509Certificate) CertificateFactory.getInstance("X.509")
                                .generateCertificate(source);
                        if (source.available() != 0 || loaded.getBasicConstraints() < 0) {
                            throw unavailable("App Attest root certificate is invalid");
                        }
                        loaded.checkValidity();
                        loaded.verify(loaded.getPublicKey());
                        rootCertificate = loaded;
                    } catch (IOException | GeneralSecurityException | IllegalArgumentException e) {
                        throw unavailable("App Attest root certificate is unavailable or invalid");
                    }
                }
            }
        }
        try {
            loaded.checkValidity();
        } catch (GeneralSecurityException e) {
            throw unavailable("App Attest root certificate is outside its validity period");
        }
        return loaded;
    }

    private JsonNode readCbor(byte[] encoded) {
        return readCbor(encoded, false);
    }

    private JsonNode readCbor(byte[] encoded, boolean integerLabels) {
        requireBytes(encoded, MAX_CBOR_BYTES, "Invalid CBOR size");
        try {
            // Preflight also rejects CBOR tags and caps the number of small containers/values.
            try (CBORParser parser = (CBORParser) cbor.getFactory().createParser(encoded)) {
                int tokens = 0;
                while (parser.nextToken() != null) {
                    if (++tokens > 256 || parser.getCurrentTag() != -1) {
                        throw malformed("Unsupported or oversized CBOR");
                    }
                    if (parser.currentToken() == JsonToken.FIELD_NAME) {
                        // Jackson normalizes integer map keys to strings. Inspect the original
                        // major type so text labels cannot impersonate COSE integer labels.
                        int offset = Math.toIntExact(parser.currentTokenLocation().getByteOffset());
                        if (offset < 0 || offset >= encoded.length) {
                            throw malformed("Invalid CBOR map key");
                        }
                        int majorType = (encoded[offset] & 0xff) >>> 5;
                        if (integerLabels ? majorType > 1 : majorType != 3) {
                            throw malformed("Invalid CBOR map key type");
                        }
                    }
                }
            }
            try (JsonParser parser = cbor.getFactory().createParser(encoded)) {
                JsonNode value = cbor.readTree(parser);
                if (value == null || !value.isObject() || parser.nextToken() != null) {
                    throw malformed("Expected a single CBOR map without trailing data");
                }
                return value;
            }
        } catch (IOException | IllegalArgumentException e) {
            throw malformed("Malformed CBOR");
        }
    }

    private static void requireFields(JsonNode object, Set<String> allowed) {
        if (object == null || !object.isObject()) {
            throw malformed("Expected CBOR map");
        }
        var names = object.fieldNames();
        while (names.hasNext()) {
            if (!allowed.contains(names.next())) {
                throw malformed("Unsupported CBOR field");
            }
        }
    }

    private static byte[] binary(JsonNode node, int maximum, String message) {
        if (node == null || !node.isBinary()) {
            throw malformed(message);
        }
        try {
            byte[] bytes = node.binaryValue();
            requireBytes(bytes, maximum, message);
            return bytes;
        } catch (IOException e) {
            throw malformed(message);
        }
    }

    private static void requireBytes(byte[] bytes, int maximum, String message) {
        if (bytes == null || bytes.length == 0 || bytes.length > maximum) {
            throw malformed(message);
        }
    }

    private static byte[] decodeKeyId(String keyId) {
        if (keyId == null || keyId.length() > 44) {
            throw malformed("Invalid key ID");
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(keyId);
            if (decoded.length != 32) {
                throw malformed("Key ID must contain 32 bytes");
            }
            return decoded;
        } catch (IllegalArgumentException e) {
            throw malformed("Invalid base64 key ID");
        }
    }

    private static List<X509Certificate> certificates(JsonNode chain) {
        if (chain == null || !chain.isArray() || chain.isEmpty() || chain.size() > 5) {
            throw malformed("Invalid x5c certificate chain");
        }
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            List<X509Certificate> result = new ArrayList<>();
            for (JsonNode node : chain) {
                byte[] encoded = binary(node, 16_384, "Invalid x5c certificate");
                ByteArrayInputStream input = new ByteArrayInputStream(encoded);
                X509Certificate certificate = (X509Certificate) factory.generateCertificate(input);
                if (input.available() != 0 || !Arrays.equals(encoded, certificate.getEncoded())) {
                    throw malformed("x5c certificates must be DER without trailing data");
                }
                result.add(certificate);
            }
            return result;
        } catch (GeneralSecurityException e) {
            throw malformed("Malformed x5c certificate");
        }
    }

    private static void validateChain(List<X509Certificate> certificates, X509Certificate root) {
        try {
            X509Certificate leaf = certificates.getFirst();
            boolean[] usage = leaf.getKeyUsage();
            if (leaf.getBasicConstraints() >= 0 || (usage != null && !usage[0])) {
                throw invalid("Invalid attestation leaf certificate");
            }
            List<X509Certificate> path = new ArrayList<>(certificates);
            if (path.getLast().equals(root)) {
                path.removeLast();
            }
            if (path.isEmpty()) {
                throw invalid("Missing attestation leaf certificate");
            }
            PKIXParameters parameters = new PKIXParameters(Set.of(new TrustAnchor(root, null)));
            // Validate only the supplied path against the configured Apple root. No network
            // retrieval or implicit platform trust; receipt/risk assessment is a separate concern.
            parameters.setRevocationEnabled(false);
            CertPathValidator.getInstance("PKIX").validate(
                    CertificateFactory.getInstance("X.509").generateCertPath(path), parameters);
        } catch (GeneralSecurityException e) {
            throw invalid("Untrusted or invalid attestation certificate chain");
        }
    }

    private void checkHeader(byte[] authData, boolean attestation) {
        int flags = authData[32] & 0xff;
        if ((flags & FLAG_ED) != 0 || ((flags & FLAG_AT) != 0) != attestation
                || (flags & 0x22) != 0 || ((flags & 0x10) != 0 && (flags & 0x08) == 0)) {
            throw malformed("Unsupported authenticator flags");
        }
        if (!MessageDigest.isEqual(Arrays.copyOf(authData, 32),
                sha256(appId.getBytes(StandardCharsets.UTF_8)))) {
            throw invalid("App identity does not match");
        }
    }

    private static long counter(byte[] authData) {
        return Integer.toUnsignedLong(ByteBuffer.wrap(authData, 33, 4).getInt());
    }

    private static ECPublicKey p256Key(PublicKey key) {
        if (!(key instanceof ECPublicKey ec)) {
            throw invalid("Expected an EC P-256 key");
        }
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec expected = parameters.getParameterSpec(ECParameterSpec.class);
            ECParameterSpec actual = ec.getParams();
            if (actual == null || !expected.getCurve().equals(actual.getCurve())
                    || !expected.getGenerator().equals(actual.getGenerator())
                    || !expected.getOrder().equals(actual.getOrder())
                    || expected.getCofactor() != actual.getCofactor()) {
                throw invalid("Expected an EC P-256 key");
            }
            BigInteger x = ec.getW().getAffineX();
            BigInteger y = ec.getW().getAffineY();
            BigInteger p = ((ECFieldFp) expected.getCurve().getField()).getP();
            if (x == null || y == null || x.signum() < 0 || y.signum() < 0
                    || x.compareTo(p) >= 0 || y.compareTo(p) >= 0
                    || !y.multiply(y).mod(p).equals(x.multiply(x).multiply(x)
                    .add(expected.getCurve().getA().multiply(x))
                    .add(expected.getCurve().getB()).mod(p))) {
                throw invalid("Invalid EC public point");
            }
            return ec;
        } catch (GeneralSecurityException e) {
            throw unavailable("EC P-256 support is unavailable");
        }
    }

    private static byte[] uncompressedPoint(ECPublicKey key) {
        byte[] point = new byte[65];
        point[0] = 0x04;
        copyCoordinate(key.getW().getAffineX(), point, 1);
        copyCoordinate(key.getW().getAffineY(), point, 33);
        return point;
    }

    private static void copyCoordinate(BigInteger coordinate, byte[] target, int offset) {
        byte[] encoded = coordinate.toByteArray();
        int length = Math.min(encoded.length, 32);
        System.arraycopy(encoded, encoded.length - length, target, offset + 32 - length, length);
    }

    private static void validateCoseKey(JsonNode cose, byte[] point) {
        requireFields(cose, Set.of("1", "3", "-1", "-2", "-3"));
        if (cose.size() != 5) {
            throw malformed("Incomplete COSE EC2 key");
        }
        requireCoseInteger(cose.get("1"), 2);
        requireCoseInteger(cose.get("3"), -7);
        requireCoseInteger(cose.get("-1"), 1);
        byte[] x = binary(cose.get("-2"), 32, "Invalid COSE x coordinate");
        byte[] y = binary(cose.get("-3"), 32, "Invalid COSE y coordinate");
        if (x.length != 32 || y.length != 32
                || !MessageDigest.isEqual(x, Arrays.copyOfRange(point, 1, 33))
                || !MessageDigest.isEqual(y, Arrays.copyOfRange(point, 33, 65))) {
            throw invalid("COSE key does not match the attestation certificate");
        }
    }

    private static void requireCoseInteger(JsonNode node, int expected) {
        if (node == null || !node.isIntegralNumber() || !node.canConvertToInt()) {
            throw malformed("Invalid COSE integer");
        }
        if (node.intValue() != expected) {
            throw invalid("Expected a COSE EC2 ES256 P-256 key");
        }
    }

    private static void verifyNonce(X509Certificate leaf, byte[] expected) {
        byte[] extension = leaf.getExtensionValue(NONCE_OID);
        if (extension == null) {
            throw invalid("Missing App Attest nonce extension");
        }
        try {
            ASN1Primitive outer = ASN1Primitive.fromByteArray(extension);
            if (!(outer instanceof ASN1OctetString wrapper)) {
                throw invalid("Invalid App Attest nonce extension");
            }
            ASN1Primitive value = ASN1Primitive.fromByteArray(wrapper.getOctets());
            if (!(value instanceof ASN1Sequence sequence) || sequence.size() != 1
                    || !(sequence.getObjectAt(0) instanceof ASN1TaggedObject tagged)
                    || tagged.getTagClass() != BERTags.CONTEXT_SPECIFIC || tagged.getTagNo() != 1
                    || !tagged.isExplicit()
                    || !(tagged.getExplicitBaseObject() instanceof ASN1OctetString nonce)
                    || !Arrays.equals(value.getEncoded("DER"), wrapper.getOctets())
                    || !MessageDigest.isEqual(expected, nonce.getOctets())) {
                throw invalid("App Attest nonce does not match");
            }
        } catch (IOException | IllegalArgumentException | IllegalStateException e) {
            throw invalid("Invalid App Attest nonce extension");
        }
    }

    private static void validateEcdsaEncoding(byte[] encoded, BigInteger order) {
        try {
            ASN1Primitive value = ASN1Primitive.fromByteArray(encoded);
            if (!(value instanceof ASN1Sequence sequence) || sequence.size() != 2
                    || !(sequence.getObjectAt(0) instanceof org.bouncycastle.asn1.ASN1Integer r)
                    || !(sequence.getObjectAt(1) instanceof org.bouncycastle.asn1.ASN1Integer s)
                    || r.getValue().signum() <= 0 || r.getValue().compareTo(order) >= 0
                    || s.getValue().signum() <= 0 || s.getValue().compareTo(order) >= 0
                    || !Arrays.equals(encoded, value.getEncoded("DER"))) {
                throw malformed("Invalid DER ECDSA signature");
            }
        } catch (IOException | IllegalArgumentException e) {
            throw malformed("Invalid DER ECDSA signature");
        }
    }

    private static byte[] sha256(byte[]... parts) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (byte[] part : parts) {
                digest.update(part);
            }
            return digest.digest();
        } catch (GeneralSecurityException e) {
            throw unavailable("SHA-256 support is unavailable");
        }
    }

    private static ResponseStatusException malformed(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }

    private static ResponseStatusException invalid(String message) {
        return new ResponseStatusException(HttpStatus.FORBIDDEN, message);
    }

    private static ResponseStatusException unavailable(String message) {
        return new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, message);
    }
}
