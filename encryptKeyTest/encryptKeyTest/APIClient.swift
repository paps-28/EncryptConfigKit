//
//  APIClient.swift
//  encryptKeyTest
//
//  Created by Pedro Alberto Parra Solis on 23/09/26.
//


import Foundation

final class APIClient {
    
    private let baseURL = URL(string: "http://localhost:8080")!
    
    func post<Body: Encodable, Response: Decodable>(
        endpoint: String,
        body: Body
    ) async throws -> Response {
        
        let url = baseURL.appendingPathComponent(endpoint)
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        
        request.httpBody = try JSONEncoder().encode(body)
        
        let (data, response) = try await URLSession.shared.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse else {
            throw APIError.invalidResponse
        }
        
        guard 200...299 ~= httpResponse.statusCode else {
            throw APIError.httpError(statusCode: httpResponse.statusCode)
        }
        
        return try JSONDecoder().decode(Response.self, from: data)
    }
}

enum APIError: Error {
    case invalidResponse
    case httpError(statusCode: Int)
}
