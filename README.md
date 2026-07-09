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

## Algoritmo de cifrado RSA

La aplicación utiliza el siguiente algoritmo para descifrar la llave AES recibida desde el backend:

```text
RSA-OAEP-SHA256
```

Por lo tanto, el backend debe utilizar exactamente el mismo algoritmo para cifrar la llave AES.

Es importante que exista compatibilidad entre ambos extremos respecto a:

```text
Padding

OAEP Hash Algorithm

MGF1 Hash Algorithm
```

La configuración recomendada es:

```text
RSA Key Size:       3072 bits

Padding:            OAEP

OAEP Hash:          SHA-256

MGF1 Hash:          SHA-256
```

El flujo criptográfico es:

```text
AES Key
   │
   ▼
RSA Public Key
   │
   ▼
RSA-OAEP-SHA256
   │
   ▼
Encrypted AES Key
```

La aplicación realiza la operación inversa:

```text
Encrypted AES Key
        │
        ▼
RSA Private Key
        │
        ▼
RSA-OAEP-SHA256
        │
        ▼
AES Key
```

## Flujo del backend

El backend debe realizar las siguientes operaciones:

```text
1. Recibir la llave pública RSA de la aplicación.

2. Validar la identidad, sesión o autorización del cliente.

3. Identificar la llave AES correspondiente al ambiente y versión solicitados.

4. Cifrar la llave AES utilizando la llave pública RSA recibida.

5. Utilizar RSA-OAEP-SHA256 como algoritmo de cifrado.

6. Convertir el resultado cifrado a Base64.

7. Regresar la llave AES cifrada a la aplicación.
```

La llave AES nunca debe enviarse en texto plano.

## Compatibilidad con diferentes tecnologías backend

La operación de cifrado puede implementarse utilizando cualquier tecnología backend que soporte RSA-OAEP-SHA256.

Entre las tecnologías más comunes se encuentran:

```text
Java

.NET

Go

Node.js

Python

OpenSSL
```

La tecnología utilizada por el servidor no afecta el funcionamiento del paquete.

La única condición es que el backend utilice parámetros criptográficos compatibles con la implementación utilizada por la aplicación iOS.

## Ejemplos de backend: cifrar la llave AES con la llave pública RSA

La aplicación genera localmente un par de llaves RSA y envía únicamente la llave pública al backend.

El backend utiliza esta llave pública para cifrar la llave AES que previamente fue utilizada por el plugin durante el proceso de compilación para cifrar el archivo de configuración.

Es importante que el backend utilice **exactamente la misma llave AES utilizada por el plugin**. El servidor no debe generar una nueva llave AES en cada solicitud.

El cifrado de la llave AES debe realizarse utilizando:

```text
RSA-OAEP-SHA256
```

El flujo general es:

```text
Plugin
   │
   │ Utiliza AES Key
   ▼
Cifra SecretsConfig.plist
   │
   ▼
SecretsConfig.plist.enc
   │
   ▼
App Bundle


Backend
   │
   │ Almacena la misma AES Key
   ▼
Recibe RSA Public Key de la aplicación
   │
   ▼
Cifra AES Key utilizando RSA-OAEP-SHA256
   │
   ▼
Encrypted AES Key
   │
   ▼
Base64
   │
   ▼
Aplicación


Aplicación
   │
   │ RSA Private Key
   ▼
Descifra Encrypted AES Key
   │
   ▼
AES Key
   │
   ▼
Descifra SecretsConfig.plist.enc
```

El backend debe regresar la llave AES cifrada codificada en Base64.

Ejemplo de respuesta:

```json
{
    "encrypted_key": "BASE64_RSA_ENCRYPTED_AES_KEY"
}
```

### Formato de la llave pública

La aplicación puede enviar la llave pública RSA utilizando formato PEM.

Dependiendo de cómo se exporte la llave pública desde iOS, puede utilizarse alguno de los siguientes formatos.

Formato PKCS#1:

```text
-----BEGIN RSA PUBLIC KEY-----
BASE64_PUBLIC_KEY
-----END RSA PUBLIC KEY-----
```

Formato X.509 SubjectPublicKeyInfo:

```text
-----BEGIN PUBLIC KEY-----
BASE64_PUBLIC_KEY
-----END PUBLIC KEY-----
```

Las diferentes tecnologías backend pueden esperar formatos distintos para importar una llave pública RSA.

Por este motivo, antes de utilizar los ejemplos siguientes debe verificarse qué formato de llave pública acepta la librería criptográfica utilizada.

No es suficiente cambiar únicamente los encabezados del PEM. La representación binaria DER también debe corresponder al formato esperado.

Los siguientes ejemplos muestran cómo cifrar la llave AES utilizando la llave pública RSA recibida desde la aplicación mediante:

* Java
* .NET
* Go
* OpenSSL

Todos los ejemplos deben utilizar parámetros criptográficos compatibles con la aplicación iOS:

```text
RSA Padding: OAEP
OAEP Hash: SHA-256
MGF1 Hash: SHA-256
```

El resultado del cifrado debe convertirse a Base64 antes de enviarse a la aplicación.

La aplicación convierte el valor Base64 recibido a datos binarios y utiliza su llave privada RSA almacenada localmente para recuperar la llave AES original.
---

## Java example

```java
import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public final class RSAOAEPEncryptor {

    public static String encryptAESKey(
            String aesKeyBase64,
            String publicKeyPem
    ) throws Exception {

        byte[] aesKey = Base64.getDecoder().decode(aesKeyBase64);

        PublicKey publicKey = loadPublicKey(publicKeyPem);

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] encrypted = cipher.doFinal(aesKey);

        return Base64.getEncoder().encodeToString(encrypted);
    }

    private static PublicKey loadPublicKey(String publicKeyPem) throws Exception {
        String cleaned = publicKeyPem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("-----BEGIN RSA PUBLIC KEY-----", "")
                .replace("-----END RSA PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(cleaned);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);

        return KeyFactory
                .getInstance("RSA")
                .generatePublic(spec);
    }
}
```

Usage:

```java
String encryptedAESKey = RSAOAEPEncryptor.encryptAESKey(
        "BASE64_AES_KEY",
        publicKeyPemFromApp
);
```

---

## .NET example

```csharp
using System;
using System.Security.Cryptography;
using System.Text;

public static class RSAOAEPEncryptor
{
    public static string EncryptAESKey(
        string aesKeyBase64,
        string publicKeyPem
    )
    {
        byte[] aesKey = Convert.FromBase64String(aesKeyBase64);

        using RSA rsa = RSA.Create();

        rsa.ImportFromPem(publicKeyPem.ToCharArray());

        byte[] encrypted = rsa.Encrypt(
            aesKey,
            RSAEncryptionPadding.OaepSHA256
        );

        return Convert.ToBase64String(encrypted);
    }
}
```

Usage:

```csharp
string encryptedAESKey = RSAOAEPEncryptor.EncryptAESKey(
    "BASE64_AES_KEY",
    publicKeyPemFromApp
);
```

---

## Go example

```go
package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

func EncryptAESKey(
	aesKeyBase64 string,
	publicKeyPEM string,
) (string, error) {

	aesKey, err := base64.StdEncoding.DecodeString(aesKeyBase64)
	if err != nil {
		return "", err
	}

	publicKey, err := loadPublicKey(publicKeyPEM)
	if err != nil {
		return "", err
	}

	encrypted, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		publicKey,
		aesKey,
		nil,
	)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func loadPublicKey(publicKeyPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("invalid public key PEM")
	}

	if block.Type == "PUBLIC KEY" {
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("public key is not RSA")
		}

		return rsaKey, nil
	}

	if block.Type == "RSA PUBLIC KEY" {
		return x509.ParsePKCS1PublicKey(block.Bytes)
	}

	return nil, errors.New("unsupported public key type")
}
```

Usage:

```go
encryptedAESKey, err := crypto.EncryptAESKey(
	"BASE64_AES_KEY",
	publicKeyPEMFromApp,
)
```

---

## OpenSSL example

Save the public key received from the app:

```bash
cat > public_key.pem <<EOF
-----BEGIN RSA PUBLIC KEY-----
...
-----END RSA PUBLIC KEY-----
EOF
```

Create a random AES-256 key:

```bash
openssl rand -base64 32 > aes_key.base64
```

Decode it to binary:

```bash
base64 -d aes_key.base64 > aes_key.bin
```

Encrypt the AES key using RSA-OAEP-SHA256:

```bash
openssl pkeyutl \
  -encrypt \
  -pubin \
  -inkey public_key.pem \
  -in aes_key.bin \
  -out encrypted_aes_key.bin \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256 \
  -pkeyopt rsa_mgf1_md:sha256
```

Return it as Base64:

```bash
base64 encrypted_aes_key.bin
```

Response example:

```json
{
    "encrypted_key": "BASE64_RSA_ENCRYPTED_AES_KEY"
}
```

---

## Recommended backend flow

```text
1. Receive RSA public key from app
2. Validate app/session/device identity
3. Select AES key for the requested environment
4. Encrypt AES key using RSA-OAEP-SHA256
5. Return encrypted AES key as Base64
```
