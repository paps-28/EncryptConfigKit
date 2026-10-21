import Foundation
import XCTest
@testable import encryptKeyTest

@MainActor
final class AppAttestAPITests: XCTestCase {
    private let rsaPublicKey = Data([0x30, 0x82, 0x00, 0xff, 0x80, 0x01])
    private let assertionChallenge = Data(0..<32)
    private let attestationChallenge = Data(32..<64)

    func testRegisteredKeyUsesAssertionWithoutAttestation() async throws {
        let fixture = makeFixture(replies: [challengeReply(), encryptedKeyReply()])
        defer { fixture.close() }

        let result = try await fixture.api.encryptedKey(rsaPublicKey: rsaPublicKey)

        XCTAssertEqual(result.encryptedKey, "encrypted-key")
        XCTAssertEqual(fixture.provider.keyIdCalls, 1)
        XCTAssertTrue(fixture.provider.attestationChallenges.isEmpty)
        assertAssertion(fixture.provider)
        let requests = fixture.script.requests
        assertRequests(requests, paths: ["challenge", "public-key"])
        try assertChallengeRequest(requests[0], purpose: "ASSERTION")
        try assertAssertionRequest(requests[1])
        XCTAssertEqual(fixture.script.remainingReplies, 0)
    }

    func testMissingKeyRegistersWithEmpty204ThenRequestsAssertion() async throws {
        let fixture = makeFixture(replies: [
            .init(status: 404),
            challengeReply(id: "attestation-id", bytes: attestationChallenge),
            .init(status: 204),
            challengeReply(),
            encryptedKeyReply()
        ])
        defer { fixture.close() }

        let result = try await fixture.api.encryptedKey(rsaPublicKey: rsaPublicKey)

        XCTAssertEqual(result.encryptedKey, "encrypted-key")
        XCTAssertEqual(fixture.provider.keyIdCalls, 1)
        XCTAssertEqual(fixture.provider.attestationChallenges, [attestationChallenge])
        assertAssertion(fixture.provider)
        let requests = fixture.script.requests
        assertRequests(requests, paths: ["challenge", "challenge", "attest", "challenge", "public-key"])
        try assertChallengeRequest(requests[0], purpose: "ASSERTION")
        try assertChallengeRequest(requests[1], purpose: "ATTESTATION")
        XCTAssertEqual(try jsonBody(requests[2]), [
            "keyId": "test-key-id",
            "challengeId": "attestation-id",
            "attestationObject": fixture.provider.attestation.base64EncodedString()
        ])
        try assertChallengeRequest(requests[3], purpose: "ASSERTION")
        try assertAssertionRequest(requests[4])
        XCTAssertEqual(fixture.script.remainingReplies, 0)
    }

    func testRegistrationConflictContinuesWithSameKeyWithoutRotation() async throws {
        let fixture = makeFixture(replies: [
            .init(status: 404),
            challengeReply(id: "attestation-id", bytes: attestationChallenge),
            .init(status: 409),
            challengeReply(),
            encryptedKeyReply()
        ])
        defer { fixture.close() }

        let result = try await fixture.api.encryptedKey(rsaPublicKey: rsaPublicKey)

        XCTAssertEqual(result.encryptedKey, "encrypted-key")
        XCTAssertEqual(fixture.provider.keyIdCalls, 1)
        XCTAssertEqual(fixture.provider.attestationChallenges, [attestationChallenge])
        assertAssertion(fixture.provider)
        let requests = fixture.script.requests
        assertRequests(requests, paths: ["challenge", "challenge", "attest", "challenge", "public-key"])
        try assertChallengeRequest(requests[0], purpose: "ASSERTION")
        try assertChallengeRequest(requests[1], purpose: "ATTESTATION")
        try assertChallengeRequest(requests[3], purpose: "ASSERTION")
        for request in requests {
            XCTAssertEqual(try jsonBody(request)["keyId"], "test-key-id")
        }
        try assertAssertionRequest(requests[4])
        XCTAssertEqual(fixture.script.remainingReplies, 0)
    }

    func testForbiddenChallengeDoesNotRegisterOrFallBack() async throws {
        let fixture = makeFixture(replies: [.init(status: 403)])
        defer { fixture.close() }

        do {
            _ = try await fixture.api.encryptedKey(rsaPublicKey: rsaPublicKey)
            XCTFail("Expected HTTP 403")
        } catch APIError.httpError(statusCode: 403) {
            // Forbidden is terminal, not an indication that registration is needed.
        } catch {
            XCTFail("Unexpected error: \(error)")
        }

        XCTAssertEqual(fixture.provider.keyIdCalls, 1)
        XCTAssertTrue(fixture.provider.attestationChallenges.isEmpty)
        XCTAssertTrue(fixture.provider.assertions.isEmpty)
        assertRequests(fixture.script.requests, paths: ["challenge"])
    }

    func testForbiddenPublicKeyDoesNotRegisterOrFallBack() async throws {
        let fixture = makeFixture(replies: [challengeReply(), .init(status: 403)])
        defer { fixture.close() }

        do {
            _ = try await fixture.api.encryptedKey(rsaPublicKey: rsaPublicKey)
            XCTFail("Expected HTTP 403")
        } catch APIError.httpError(statusCode: 403) {
        } catch {
            XCTFail("Unexpected error: \(error)")
        }

        XCTAssertEqual(fixture.provider.keyIdCalls, 1)
        XCTAssertTrue(fixture.provider.attestationChallenges.isEmpty)
        assertAssertion(fixture.provider)
        assertRequests(fixture.script.requests, paths: ["challenge", "public-key"])
    }

    func testMalformedAssertionChallengeDoesNotInvokeSigningProvider() async throws {
        let fixture = makeFixture(replies: [malformedChallengeReply()])
        defer { fixture.close() }

        do {
            _ = try await fixture.api.encryptedKey(rsaPublicKey: rsaPublicKey)
            XCTFail("Expected invalid challenge")
        } catch {
            XCTFail("Unexpected error: \(error)")
        }

        XCTAssertEqual(fixture.provider.keyIdCalls, 1)
        XCTAssertTrue(fixture.provider.attestationChallenges.isEmpty)
        XCTAssertTrue(fixture.provider.assertions.isEmpty)
        assertRequests(fixture.script.requests, paths: ["challenge"])
    }

    func testMalformedAttestationChallengeDoesNotInvokeAttestationProvider() async throws {
        let fixture = makeFixture(replies: [.init(status: 404), malformedChallengeReply()])
        defer { fixture.close() }

        do {
            _ = try await fixture.api.encryptedKey(rsaPublicKey: rsaPublicKey)
            XCTFail("Expected invalid challenge")
        } catch {
            XCTFail("Unexpected error: \(error)")
        }

        XCTAssertEqual(fixture.provider.keyIdCalls, 1)
        XCTAssertTrue(fixture.provider.attestationChallenges.isEmpty)
        XCTAssertTrue(fixture.provider.assertions.isEmpty)
        let requests = fixture.script.requests
        assertRequests(requests, paths: ["challenge", "challenge"])
        try assertChallengeRequest(requests[1], purpose: "ATTESTATION")
    }

    private func makeFixture(replies: [AppAttestHTTPReply]) -> AppAttestFixture {
        let host = "\(UUID().uuidString.lowercased()).invalid"
        let script = AppAttestHTTPScript(replies: replies)
        AppAttestTestURLProtocol.registry.insert(script, host: host)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [AppAttestTestURLProtocol.self]
        let session = URLSession(configuration: configuration)
        let provider = AppAttestProviderStub()
        let client = APIClient()
        return AppAttestFixture(
            api: AppAttestAPI(client: client, provider: provider),
            provider: provider, session: session, script: script, host: host
        )
    }

    private func challengeReply(id: String = "assertion-id", bytes: Data? = nil) -> AppAttestHTTPReply {
        .init(status: 200, body: Data("""
        {"challengeId":"\(id)","challenge":"\((bytes ?? assertionChallenge).base64EncodedString())","expiresAt":"2026-10-21T12:00:00Z"}
        """.utf8))
    }

    private func malformedChallengeReply() -> AppAttestHTTPReply {
        .init(status: 200, body: Data("""
        {"challengeId":"invalid-id","challenge":"not!base64","expiresAt":"2026-10-21T12:00:00Z"}
        """.utf8))
    }

    private func encryptedKeyReply() -> AppAttestHTTPReply {
        .init(status: 200, body: Data(#"{"encryptedKey":"encrypted-key"}"#.utf8))
    }

    private func assertAssertion(_ provider: AppAttestProviderStub) {
        XCTAssertEqual(provider.assertions.count, 1)
        XCTAssertEqual(provider.assertions.first?.challenge, assertionChallenge)
        XCTAssertEqual(provider.assertions.first?.rsaPublicKey, rsaPublicKey)
    }

    private func assertRequests(_ requests: [URLRequest], paths: [String]) {
        XCTAssertEqual(requests.map { $0.url?.path }, paths.map { "/api/crypto/app-attest/\($0)" })
        for request in requests {
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
            XCTAssertNotEqual(request.url?.path, "/api/crypto/public-key")
        }
    }

    private func jsonBody(_ request: URLRequest) throws -> [String: String] {
        let data = try XCTUnwrap(request.httpBody)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: String])
    }

    private func assertChallengeRequest(_ request: URLRequest, purpose: String) throws {
        XCTAssertEqual(try jsonBody(request), ["keyId": "test-key-id", "purpose": purpose])
    }

    private func assertAssertionRequest(_ request: URLRequest) throws {
        XCTAssertEqual(try jsonBody(request), [
            "keyId": "test-key-id",
            "challengeId": "assertion-id",
            "assertionObject": Data([0xff, 0x00, 0x81, 0x42]).base64EncodedString(),
            "publicKey": rsaPublicKey.base64EncodedString()
        ])
    }
}

@MainActor
private final class AppAttestProviderStub: AppAttestProviding {
    let attestation = Data([0x00, 0xff, 0x80, 0x22])
    private(set) var keyIdCalls = 0
    private(set) var attestationChallenges: [Data] = []
    private(set) var assertions: [(challenge: Data, rsaPublicKey: Data)] = []

    func keyId() async throws -> String {
        keyIdCalls += 1
        return "test-key-id"
    }

    func attest(challenge: Data) async throws -> Data {
        attestationChallenges.append(challenge)
        return attestation
    }

    func assertion(challenge: Data, rsaPublicKey: Data) async throws -> Data {
        assertions.append((challenge, rsaPublicKey))
        return Data([0xff, 0x00, 0x81, 0x42])
    }
}

@MainActor
private struct AppAttestFixture {
    let api: AppAttestAPI
    let provider: AppAttestProviderStub
    let session: URLSession
    let script: AppAttestHTTPScript
    let host: String

    func close() {
        session.invalidateAndCancel()
        AppAttestTestURLProtocol.registry.remove(host: host)
    }
}

nonisolated private struct AppAttestHTTPReply: Sendable {
    let status: Int
    var body = Data()
}

// URLSession callbacks run off the main actor. All mutable script state is locked.
nonisolated private final class AppAttestHTTPScript: @unchecked Sendable {
    private let lock = NSLock()
    private var replies: [AppAttestHTTPReply]
    private var recordedRequests: [URLRequest] = []

    init(replies: [AppAttestHTTPReply]) {
        self.replies = replies
    }

    var requests: [URLRequest] {
        lock.lock()
        defer { lock.unlock() }
        return recordedRequests
    }

    var remainingReplies: Int {
        lock.lock()
        defer { lock.unlock() }
        return replies.count
    }

    func reply(for request: URLRequest) throws -> AppAttestHTTPReply {
        lock.lock()
        defer { lock.unlock() }
        recordedRequests.append(request)
        guard !replies.isEmpty else { throw URLError(.badServerResponse) }
        return replies.removeFirst()
    }
}

nonisolated private final class AppAttestScriptRegistry: @unchecked Sendable {
    private let lock = NSLock()
    private var scripts: [String: AppAttestHTTPScript] = [:]

    func insert(_ script: AppAttestHTTPScript, host: String) {
        lock.lock()
        defer { lock.unlock() }
        scripts[host] = script
    }

    func remove(host: String) {
        lock.lock()
        defer { lock.unlock() }
        scripts.removeValue(forKey: host)
    }

    func script(host: String) -> AppAttestHTTPScript? {
        lock.lock()
        defer { lock.unlock() }
        return scripts[host]
    }
}

nonisolated private final class AppAttestTestURLProtocol: URLProtocol, @unchecked Sendable {
    static let registry = AppAttestScriptRegistry()

    override class func canInit(with request: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        do {
            guard let url = request.url, let host = url.host,
                  let script = Self.registry.script(host: host) else {
                throw URLError(.unsupportedURL)
            }
            var capturedRequest = request
            // URLSession may replace httpBody with a stream before invoking URLProtocol.
            if capturedRequest.httpBody == nil, let stream = capturedRequest.httpBodyStream {
                stream.open()
                defer { stream.close() }
                var body = Data()
                var buffer = [UInt8](repeating: 0, count: 4096)
                while true {
                    let count = stream.read(&buffer, maxLength: buffer.count)
                    if count < 0 { throw stream.streamError ?? URLError(.cannotDecodeRawData) }
                    if count == 0 { break }
                    body.append(contentsOf: buffer.prefix(count))
                }
                capturedRequest.httpBody = body
            }
            let reply = try script.reply(for: capturedRequest)
            guard let response = HTTPURLResponse(
                url: url, statusCode: reply.status, httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "application/json"]
            ) else {
                throw URLError(.badServerResponse)
            }
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            if !reply.body.isEmpty { client?.urlProtocol(self, didLoad: reply.body) }
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}
