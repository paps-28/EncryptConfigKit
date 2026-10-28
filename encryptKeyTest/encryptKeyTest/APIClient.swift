//
//  APIClient.swift
//  encryptKeyTest
//

import Foundation
import OSLog

@MainActor
final class APIClient {
    let baseURL: URL?
    private let session: URLSession

    init(baseURL: URL? = nil, session: URLSession = .shared) {
        self.baseURL = baseURL ?? (Bundle.main.object(forInfoDictionaryKey: "AppAttestAPIBaseURL") as? String)
            .flatMap(URL.init(string:))
        self.session = session
    }

    func post<Body: Encodable, Response: Decodable>(
        endpoint: String,
        body: Body
    ) async throws -> Response {
        let data = try await send(endpoint: endpoint, body: body)
        do {
            return try JSONDecoder().decode(Response.self, from: data)
        } catch {
            AppAttestLog.failure(error, stage: "http.decodeResponse")
            throw error
        }
    }

    // Registration returns HTTP 204, with no JSON body to decode.
    func post<Body: Encodable>(endpoint: String, body: Body) async throws {
        _ = try await send(endpoint: endpoint, body: body)
    }

    private func send<Body: Encodable>(endpoint: String, body: Body) async throws -> Data {
        guard let baseURL,
              ["https", "http"].contains(baseURL.scheme?.lowercased() ?? ""),
              let host = baseURL.host, !host.isEmpty,
              baseURL.user == nil, baseURL.password == nil,
              baseURL.query == nil, baseURL.fragment == nil else {
            AppAttestLog.network.error("Invalid backend base URL configuration")
            throw APIError.invalidBaseURL
        }
        let url = baseURL.appendingPathComponent(endpoint.trimmingCharacters(in: CharacterSet(charactersIn: "/")))
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = 30
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpBody = try JSONEncoder().encode(body)

        let operation: String
        switch endpoint {
        case "/api/crypto/app-attest/challenge": operation = "challenge"
        case "/api/crypto/app-attest/attest": operation = "attest"
        case "/api/crypto/app-attest/public-key": operation = "public-key"
        default: operation = "other"
        }
        let requestTrace = String(UUID().uuidString.prefix(8))
        AppAttestLog.network.info("request=\(requestTrace, privacy: .public) POST operation=\(operation, privacy: .public) started")
        let started = Date()
        do {
            let (data, response) = try await session.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse else {
                throw APIError.invalidResponse
            }
            let elapsed = Int(Date().timeIntervalSince(started) * 1000)
            AppAttestLog.network.info("request=\(requestTrace, privacy: .public) operation=\(operation, privacy: .public) status=\(httpResponse.statusCode) duration_ms=\(elapsed)")
            guard 200...299 ~= httpResponse.statusCode else {
                throw APIError.httpError(statusCode: httpResponse.statusCode)
            }
            return data
        } catch {
            AppAttestLog.failure(error, stage: "http.\(operation)")
            throw error
        }
    }
}

enum APIError: LocalizedError {
    case invalidBaseURL
    case invalidResponse
    case httpError(statusCode: Int)

    var errorDescription: String? {
        switch self {
        case .invalidBaseURL:
            return "Configura APP_ATTEST_API_BASE_URL con una URL válida y accesible desde el dispositivo."
        case .invalidResponse:
            return "El servidor devolvió una respuesta HTTP inválida."
        case .httpError(let statusCode):
            return "El servidor de App Attest devolvió HTTP \(statusCode)."
        }
    }
}
