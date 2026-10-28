# Claves EC y Secure Enclave

`ECKeyManager` implementa `AsymmetricKeyManaging` con claves NIST P-256.
RSA no está soportado por Secure Enclave; `RSAKeyManager` conserva su privada en Keychain.

## Generación y persistencia

1. `generateKeyPairIfNeeded()` busca una clave con el mismo tag. Los errores de
   acceso se propagan; no se interpretan como ausencia ni provocan reemplazos.
2. `SecKeyCreateRandomKey` recibe el tipo EC, 256 bits y
   `kSecAttrTokenIDSecureEnclave`. Secure Enclave genera el secreto privado y el
   par público asociado. Conceptualmente, la pública es el punto Q = d × G de
   la curva; d es el secreto privado.
3. `kSecAttrIsPermanent` persiste la clave protegida y sus metadatos en Keychain.
   Esto no significa guardar bytes privados en claro: únicamente el Secure Enclave
   de ese dispositivo puede utilizar el material protegido.
4. La aplicación recibe una referencia `SecKey`, no los bytes privados.
   `SecKeyCopyPublicKey` obtiene la pública, que sí se puede exportar.
   `publicKeyBase64()` devuelve DER SubjectPublicKeyInfo en Base64;
   `publicKeyPEM()` devuelve el mismo tipo de clave en formato PEM.

La protección `WhenUnlockedThisDeviceOnly` requiere que el dispositivo esté
desbloqueado. No se exige Face ID/Touch ID: `privateKeyUsage` permite la operación
privada, pero no añade autenticación biométrica.

## Uso

```swift
import EncryptConfigCore
import Foundation

let manager = ECKeyManager(tag: "com.example.config.ec.v1")
try manager.generateKeyPairIfNeeded()
let publicKeyForServer = try manager.publicKeyBase64()

// Enviar publicKeyForServer al servidor autenticado.
// Al recibir los bytes de un mensaje ECIES compatible:
func decryptResponse(_ ciphertext: Data) throws -> Data {
    try manager.decrypt(ciphertext)
}
```

El servidor necesita cifrar con el formato exacto de
`eciesEncryptionCofactorX963SHA256AESGCM` de Apple. Un mensaje RSA o un formato
ECIES distinto no es intercambiable.

ECIES combina una clave efímera del emisor, acuerdo ECDH, derivación X9.63/SHA-256
y cifrado autenticado AES-GCM. Al descifrar, Security usa la referencia privada
para realizar la operación de curva elíptica mediante Secure Enclave. La privada
no sale en claro. El resultado descifrado sí llega a la memoria de la aplicación;
esto incluye una clave AES si ese era el contenido del mensaje.

Una instancia nueva con el mismo tag y la misma identidad de acceso recupera la
clave persistida. El tag identifica la clave; no es una contraseña.
Eliminarla con `deleteKeyPair()` impide descifrar los mensajes destinados a ella.
No se puede importar una privada existente a Secure Enclave.

## Pruebas y error -34018

`-34018` corresponde a falta de entitlements. Disponer del hardware no garantiza
que el proceso de pruebas tenga una identidad autorizada para Keychain.

- Las pruebas del paquete validan exportación, descifrado, rechazo de mensajes
  alterados y propagación de errores mediante almacenes en memoria.
- `encryptKeyTestTests/KeyPersistenceIntegrationTests.swift` valida persistencia
  RSA y generación/descifrado/no exportabilidad EC en la app anfitriona.
  Abrir `encryptKeyTest/encryptKeyTest.xcodeproj`, seleccionar el esquema
  `encryptKeyTest` y ejecutar esas pruebas con una app firmada.
- La prueba EC requiere un dispositivo físico compatible o un Mac con Secure
  Enclave. En simulador se omite por falta de hardware.
- La firma y los permisos de Keychain pertenecen a la app anfitriona, no a la
  biblioteca Swift Package. Un error de permisos sigue siendo un fallo de la
  prueba de integración; no se convierte en un éxito ni activa claves software.

Documentación de Apple:
[Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave),
[Keychain en macOS](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains).
