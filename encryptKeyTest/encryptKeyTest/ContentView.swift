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
                    keyProvider: LocalKeyProvider()
                )
                
                do {
                    let rsaProvider = RSAKeyManager(algorithm: .rsaEncryptionOAEPSHA512)
                    try rsaProvider.generateKeyPairIfNeeded()
                    
                    rsaPublicKey = try rsaProvider.publicKeyPEM()
                    print(rsaPublicKey)
                    
                    let dataEnc = "jUVl4q1hTegmaTHLzlm4oVsWAk2KdhJip1xJ1h5WvuTIQbo7llbILD8Dc22GLC7xl26tPX+m6u7ECVA6/vqxm0tQ69m0ui2djy1HETX/yKhbDy7c4xE8RH2CtM1Rw/Nzdq8Za4kh7D7MMcLEPmeOV2b7m25w4OKeum40EoaZP2vbgOsR4iCCXOMLw1b5ljYV+32nvAUypgYQ46UtLf7V4YMERUhCG14FnouOgJAkVKVmyqePoVwdttsLfnkuF8rID2Kx+qd7C1uikQ6OLOIwFIQrl2TcCZ9gX5rCTG8rXNByOPERPjUbhcjZq/V/4JH/P3xmYqdIst8H4S95kOvMY0xnft5zfpMp/OSkjbCC+IqRGPoeWRWo/ub0qzIBMsSv4FsMHXJX0aefwJfmSQZU/SBxZsgxGslQyvvRlM83DqsSmBES5z40oEy2hB+7NFcOR4qE9YVRdREiYDUJ14fk2yZMxMx+4Fg2cHjA1UFbB/9UIRA3sXfLo5DYcjpJ4ofk"
                    
                    let decrypted = try rsaProvider.decrypt(Data(base64Encoded: dataEnc)!)
                    print(decrypted.base64EncodedString())
                    
                    //MARK: enviar rsaPublickKey al servidor y desencriptar respuesta de esta manera
                    //
                    // try rsaProvider.decrypt(data)
                    //
                    //
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
