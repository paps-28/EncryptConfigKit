# EncryptConfigKit

`EncryptConfigKit` es un Swift Package diseñado para proteger archivos de configuración sensibles durante el proceso de compilación de una aplicación iOS.

El paquete utiliza dos mecanismos criptográficos principales:

* **AES-GCM** para cifrar el archivo de configuración durante el proceso de compilación.
* **RSA** para realizar el intercambio seguro de la llave AES entre la aplicación y el servidor.

La llave AES utilizada por el plugin para cifrar el archivo es la misma llave AES almacenada en el servidor.

La llave AES nunca debe almacenarse dentro del código fuente de la aplicación ni incluirse dentro del bundle final.

## Arquitectura general

El flujo se divide en dos etapas.

### Build Time

Durante la compilación:

```text
SecretsConfig.plist
        │
        ▼
EncryptConfigPlugin
        │
        │ AES Key
        ▼
AES-GCM Encryption
        │
        ▼
SecretsConfig.plist.enc
        │
        ▼
App Bundle
```

El plugin obtiene la llave AES desde un mecanismo seguro configurado para el entorno de compilación.

La misma llave AES debe existir en el servidor.

El archivo original `SecretsConfig.plist` no debe incluirse dentro del bundle final de la aplicación.

### Runtime

Cuando la aplicación se ejecuta:

```text
Application
     │
     ▼
Generate RSA Key Pair
     │
     ├──────────────► Public Key
     │                     │
     │                     ▼
     │                  Server
     │                     │
     │                     │ Encrypt AES Key
     │                     │ using RSA Public Key
     │                     ▼
     │              Encrypted AES Key
     │                     │
     ◄─────────────────────┘
     │
     ▼
Decrypt AES Key
using RSA Private Key
     │
     ▼
Decrypt SecretsConfig.plist.enc
     │
     ▼
Secrets available in memory
```

La llave privada RSA permanece almacenada en el dispositivo y nunca debe enviarse al servidor.

## Instalación

Agrega `EncryptConfigKit` como dependencia utilizando Swift Package Manager.

```text
File
→ Add Package Dependencies
→ URL del repositorio EncryptConfigKit
```

Después agrega los productos necesarios al target de la aplicación.

```text
EncryptConfigRuntime
EncryptConfigPlugin
```

## Estructura del paquete

```text
EncryptConfigKit
│
├── Sources
│
│   ├── EncryptConfigCore
│   │
│   │   └── Implementación criptográfica AES-GCM
│   │
│   ├── EncryptConfigRuntime
│   │
│   │   ├── RSAKeyPairGenerator
│   │   ├── KeychainKeyStore
│   │   ├── SecretsDecryptor
│   │   └── KeyExchangeClient
│   │
│   └── EncryptConfigCLI
│       │
│       └── Ejecutable utilizado por el plugin
│
├── Plugins
│
│   └── EncryptConfigPlugin
│
└── Tests
    │
    ├── EncryptConfigCoreTests
    └── EncryptConfigRuntimeTests
```

## Configuración del archivo de secretos

Crea un archivo:

```text
config/SecretsConfig.plist
```

Ejemplo:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN">
<plist version="1.0">

<dict>

    <key>API_URL</key>
    <string>https://api.example.com</string>

    <key>CLIENT_ID</key>
    <string>example-client-id</string>

</dict>

</plist>
```

El archivo original debe excluirse de `Copy Bundle Resources`.

Solamente el archivo cifrado debe formar parte de la aplicación final:

```text
SecretsConfig.plist.enc
```

## Configuración de la llave AES

El plugin necesita recibir la llave AES utilizada para cifrar el archivo.

Ejemplo mediante una variable de entorno:

```text
CONFIG_MASTER_SECRET
```

La llave no debe almacenarse en:

```text
Source Code

Info.plist

.xcconfig versionado

UserDefaults

App Bundle
```

Ejemplo de ejecución del CLI utilizado por el plugin:

```bash
EncryptConfigCLI encrypt \
    --input config/SecretsConfig.plist \
    --output SecretsConfig.plist.enc \
    --key "$CONFIG_MASTER_SECRET"
```

El servidor debe poseer exactamente la misma llave AES.

```text
Build Environment

CONFIG_MASTER_SECRET
        │
        ├──────────────────────┐
        │                      │
        ▼                      ▼

EncryptConfigPlugin         Backend

Encrypt File               Encrypt AES Key
```

## Generación del par de llaves RSA

Durante la primera ejecución de la aplicación se genera un par de llaves RSA.

```swift
let keyManager = RSAKeyManager()

try keyManager.generateKeyPairIfNeeded()
```

Internamente se generan:

```text
RSA Private Key
RSA Public Key
```

La llave privada debe almacenarse en Keychain.

La llave pública puede obtenerse para enviarse al servidor.

```swift
let publicKey = try keyManager.loadPublicKey()
```

La llave privada nunca debe abandonar el dispositivo.

## Identificador de las llaves

Las llaves RSA deben utilizar un identificador único.

Ejemplo:

```swift
let tag = "\(Bundle.main.bundleIdentifier ?? "application").encryptconfig.rsa.private"
```

Para la llave pública:

```swift
let tag = "\(Bundle.main.bundleIdentifier ?? "application").encryptconfig.rsa.public"
```

Esto permite que el Swift Package utilice automáticamente el `Bundle Identifier` de la aplicación host.

## Enviar la llave pública al servidor

La aplicación obtiene la representación de la llave pública:

```swift
let publicKeyData = try keyManager.publicKeyData()

let publicKeyBase64 = publicKeyData.base64EncodedString()
```

Después envía la llave pública al servidor.

Ejemplo conceptual:

```text
POST /encryption/register-key
```

Request:

```json
{
    "public_key": "BASE64_RSA_PUBLIC_KEY"
}
```

## Respuesta del servidor

El servidor utiliza la llave pública RSA para cifrar la misma llave AES utilizada durante el proceso de compilación.

```text
AES Key
   │
   ▼
RSA Encrypt
   │
   │ Public Key
   ▼
Encrypted AES Key
```

Ejemplo de respuesta:

```json
{
    "encrypted_key": "BASE64_RSA_ENCRYPTED_AES_KEY"
}
```

## Descifrar la llave AES

La aplicación recibe la llave AES cifrada.

```swift
let encryptedKey = Data(base64Encoded: response.encryptedKey)
```

Después utiliza la llave privada RSA almacenada en Keychain.

```swift
let aesKey = try keyManager.decrypt(encryptedKey)
```

La llave AES recuperada debe mantenerse únicamente en memoria.

No debe almacenarse permanentemente en:

```text
UserDefaults

Archivos

Base de datos

App Bundle
```

## Descifrar el archivo de configuración

Una vez obtenida la llave AES:

```swift
let secrets = try SecretsDecryptor.decrypt(
    file: "SecretsConfig.plist.enc",
    key: aesKey
)
```

El flujo completo es:

```text
SecretsConfig.plist

        │
        │ AES-GCM
        ▼

SecretsConfig.plist.enc

        │
        │ Compilado dentro de la aplicación
        ▼

Application

        │
        │ RSA Public Key
        ▼

Server

        │
        │ AES Key encrypted with RSA
        ▼

Application

        │
        │ RSA Private Key
        ▼

AES Key

        │
        │ AES-GCM
        ▼

SecretsConfig.plist

        │
        ▼

Secrets available in memory
```

## Consideraciones de seguridad

La llave privada RSA nunca debe salir del dispositivo.

La llave AES nunca debe incluirse dentro del binario de la aplicación.

El archivo `SecretsConfig.plist` original no debe formar parte del bundle final.

La llave AES debe mantenerse únicamente en memoria durante el tiempo necesario para descifrar la configuración.

El servidor debe validar la identidad de la aplicación, dispositivo o sesión antes de entregar la llave AES cifrada.

Para instalaciones nuevas puede generarse un nuevo par RSA.

Para reinstalaciones debe definirse explícitamente la política de reutilización o regeneración de llaves.

Para rotación de llaves AES puede utilizarse un identificador de versión:

```json
{
    "key_id": "config-key-v2",
    "encrypted_key": "BASE64_RSA_ENCRYPTED_AES_KEY"
}
```

El archivo cifrado puede incluir el mismo `key_id` para indicar qué llave debe solicitar la aplicación.

## Resumen

```text
BUILD TIME

Server AES Key
       │
       ▼
Build Environment
       │
       ▼
EncryptConfigPlugin
       │
       ▼
AES-GCM Encrypt
       │
       ▼
SecretsConfig.plist.enc
       │
       ▼
App Bundle


RUNTIME

Application
       │
       ▼
Generate RSA Key Pair
       │
       ├────────────► Public Key ───────────► Server
       │                                      │
       │                                      ▼
       │                              Encrypt AES Key
       │                               using RSA Public Key
       │                                      │
       │                                      ▼
       ◄──────────────────────────── Encrypted AES Key
       │
       ▼
RSA Private Key
       │
       ▼
Decrypt AES Key
       │
       ▼
Decrypt SecretsConfig.plist.enc
       │
       ▼
Secrets available in memory
```
