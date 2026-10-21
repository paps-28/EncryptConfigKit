//
//  ContentView.swift
//  encryptKeyTest
//

import SwiftUI
import EncryptConfigRuntime

struct ContentView: View {
    @State private var status = "Validando la app con App Attest…"
    @State private var isLoading = false

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "checkmark.shield")
                .imageScale(.large)
                .foregroundStyle(.tint)
            Text(status)
                .multilineTextAlignment(.center)
            if isLoading {
                ProgressView()
            } else {
                Button("Cargar configuración") {
                    Task { await loadConfiguration() }
                }
            }
        }
        .padding()
        .task { await loadConfiguration() }
    }

    @MainActor
    private func loadConfiguration() async {
        guard !isLoading else { return }
        isLoading = true
        status = "Validando la app con App Attest…"
        defer { isLoading = false }
        do {
            let loader = ConfigurationLoader(keyProvider: RemoteKeyProvider.shared)
            _ = try await loader.loadDecodable(AppConfiguration.self, from: EncryptedConfigResource.value)
            status = "App verificada. Configuración descifrada correctamente."
        } catch {
            status = error.localizedDescription
        }
    }
}

#Preview {
    ContentView()
}
