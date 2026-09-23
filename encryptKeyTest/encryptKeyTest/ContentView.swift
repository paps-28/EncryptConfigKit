//
//  ContentView.swift
//  encryptKeyTest
//
//  Created by Pedro Alberto Parra on 30/06/26.
//

import SwiftUI
import EncryptConfigRuntime
import EncryptConfigCore
import Security

struct ContentView: View {
    
    @State var rsaPublicKey: String = ""
    
    var body: some View {
        VStack {
            Image(systemName: "globe")
                .imageScale(.large)
                .foregroundStyle(.tint)
            Text("Rsa Public Key: \n\n\(rsaPublicKey)")
        }
        .padding()
        .onAppear {
            Task {
                let loader = ConfigurationLoader(
                    keyProvider: RemoteKeyProvider()
                )
                
                do {
                    let configuration = try await loader.loadDecodable(AppConfiguration.self, from: EncryptedConfigResource.value)
                    print(configuration.HOST_NAME)
                    print(configuration.CLIENT_ID)
                    
                } catch {
                    print(error)
                }
                

                
            }
            
        }
    }
}

#Preview {
    ContentView()
}
