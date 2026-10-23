# Crypto API demo: App Attest

Backend compatible con `AppAttestManager` y `AppAttestPayload` de EncryptConfigKit. Requiere Java 25.

## Configuración

Define estas variables en el entorno del servidor antes de ejecutar `./mvnw spring-boot:run`:

- `APP_ATTEST_APP_ID`: App ID prefix + `.` + bundle identifier, por ejemplo `ABCDE12345.com.example.app`. El prefijo suele ser el Team ID; compruébalo en los entitlements de la app.
- `APP_ATTEST_ENVIRONMENT`: `production` (predeterminado) o `development`, según el entitlement `com.apple.developer.devicecheck.appattest-environment`. No se aceptan ambos entornos a la vez.
- `APP_ATTEST_AES_KEY`: texto Base64 de la clave AES utilizada para cifrar la configuración. Debe coincidir con la del plugin. Se cifra ese texto con RSA-OAEP SHA-512/MGF1 SHA-512, igual que en el endpoint original; configura el descifrado iOS con `.rsaEncryptionOAEPSHA512`.

La raíz pública de confianza se incluye en `src/main/resources/apple-app-attest-root.pem`, descargada de https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem. SHA-256 del certificado DER:

```text
1C:B9:82:3B:A2:8B:A6:AD:2D:33:A0:06:94:1D:E2:AE:4F:51:3E:F1:D4:E8:31:B9:F7:E0:FA:7B:62:42:C9:32
```

No se aceptan raíces proporcionadas por el cliente. Si falta el App ID o la clave AES requerida, la operación correspondiente devuelve `503`.

## Ejecución y logs

Con las variables anteriores configuradas en el entorno, ejecuta desde `crypto-api-demo`:

```sh
./mvnw spring-boot:run -Dspring-boot.run.arguments="--server.port=8080 --server.address=0.0.0.0 --logging.level.com.crypt.crypto_api_demo=DEBUG"
```

`0.0.0.0` expone el puerto en todas las interfaces: úsalo solo en una red de pruebas controlada; en producción aplica HTTPS y controles de acceso.

Los logs `INFO` indican inicio/éxito de challenge, registro, assertion y cifrado. `DEBUG` muestra etapas de validación (certificados, identidad, nonce y firma), propósitos, tamaños y contadores, sin sus valores criptográficos. Los rechazos HTTP se registran en `WARN` con operación, estado y razón estática; los errores inesperados en `ERROR` solo incluyen la operación y la clase de excepción, sin mensaje ni stack trace. No se registran IDs de entrada, challenges, claves RSA/AES, attestation/assertion, payloads ni cuerpos de petición. No habilites trazas de cuerpos HTTP en otros componentes.

## 1. Obtener challenge de atestación

Obtén primero `keyId` con `try await manager.getOrCreateKeyId()`.

`POST /api/crypto/app-attest/challenge`

```json
{
  "keyId": "<keyId de Apple, Base64 estándar>",
  "purpose": "ATTESTATION"
}
```

Respuesta `200`:

```json
{
  "challengeId": "<UUID>",
  "challenge": "<32 bytes aleatorios en Base64>",
  "expiresAt": "<fecha ISO-8601 UTC>"
}
```

Decodifica `challenge` a bytes; **no pases los bytes UTF-8 del texto Base64** a App Attest.

## 2. Registrar la clave atestada

En un dispositivo compatible, con el entitlement de App Attest habilitado:

```swift
let challengeData = Data(base64Encoded: challengeResponse.challenge)!
let attestation = try await manager.generateAttestation(challenge: challengeData)
// Envía attestation.base64EncodedString(), el mismo keyId y challengeId.
```

`POST /api/crypto/app-attest/attest`

```json
{
  "keyId": "<keyId>",
  "challengeId": "<challengeId del paso 1>",
  "attestationObject": "<attestation en Base64>"
}
```

Devuelve `204` y registra la clave EC verificada y su contador inicial cero. Se valida CBOR, cadena X.509 contra la raíz Apple, nonce, `SHA256(App ID)`, AAGUID del entorno, keyId y clave COSE. No se permite sobrescribir una clave registrada.

La atestación se realiza una sola vez por clave; para solicitudes posteriores usa assertions.

## 3. Pedir la clave AES con una assertion

Solicita otro challenge al mismo endpoint, ahora con `purpose: "ASSERTION"` y el `keyId` registrado. Después:

```swift
let rsaBase64 = try rsaKeyManager.publicKeyBase64()
let rsaDER = Data(base64Encoded: rsaBase64)!
let challengeData = Data(base64Encoded: challengeResponse.challenge)!
let assertion = try await manager.generateAssertion(
    challenge: challengeData,
    rsaPublicKey: rsaDER
)
// Envía rsaBase64 como publicKey y assertion.base64EncodedString().
// Debe codificar los mismos bytes rsaDER usados para generar la assertion.
```

`POST /api/crypto/app-attest/public-key`

```json
{
  "keyId": "<keyId registrado>",
  "challengeId": "<challengeId de ASSERTION>",
  "assertionObject": "<assertion en Base64>",
  "publicKey": "<RSA DER X.509 SubjectPublicKeyInfo en Base64 estándar, sin saltos ni espacios>"
}
```

Respuesta `200`:

```json
{
  "encryptedKey": "<clave AES cifrada con RSA-OAEP, en Base64>"
}
```

El endpoint protegido acepta `publicKey` **solo como Base64 estándar de DER X.509 SubjectPublicKeyInfo**, con RSA de 2048–8192 bits y un máximo de 16 384 bytes DER. No acepta PEM, espacios, saltos de línea ni PKCS#1. El endpoint original `/api/crypto/public-key` conserva su soporte PEM/Base64. Ambos usan RSA-OAEP SHA-512 con MGF1 SHA-512 para el cifrado.

El endpoint protegido primero verifica el challenge, la assertion y su contador; solo después cifra la contraseña AES configurada en `APP_ATTEST_AES_KEY`. No usa la clave hardcodeada del endpoint de demostración. La firma vincula **los mismos bytes DER originales** decodificados del Base64 y utilizados para cifrar la respuesta, no su representación textual. El backend replica exactamente el payload de Swift:

```text
clientDataHash = SHA256(UTF8("EncryptConfigKit.AppAttest.AESKey.v1") || 0x00 || challenge || rsaDER)
```

Se comprueba la firma ECDSA de `authenticatorData || clientDataHash`, el App ID y un contador uint32 estrictamente creciente. Cada entrega requiere un challenge y una assertion nuevos.

## Errores y límites

- `400`: Base64/CBOR/campos inválidos, challenge consumido, caducado o de otra clave/operación.
- `403`: prueba criptográfica inválida, identidad/entorno incorrectos o contador que no aumenta.
- `404`: clave no registrada al solicitar/verificar una assertion.
- `409`: clave ya registrada.
- `429`: límite de 10 000 challenges pendientes alcanzado.
- `503`: configuración de App Attest incompleta o almacén de 10 000 claves lleno.

Los challenges caducan a los cinco minutos y se consumen antes de verificar la prueba, incluso si esta falla. Solicita uno nuevo para reintentar. El consumo y la actualización de contadores son atómicos dentro de esta instancia. No se devuelve ningún secreto en los errores.

## Alcance de la demo y producción

**El endpoint anterior `POST /api/crypto/public-key` sigue accesible sin App Attest y entrega su clave de demostración. Elimínalo o protégelo antes de producción: no uses la misma clave de producción en ese flujo.**

El almacenamiento es en memoria y se pierde al reiniciar; no sirve para múltiples réplicas. Para producción necesitas persistencia compartida con consumo transaccional de challenges y comparación/actualización atómica de contadores. Apple no permite reatestar arbitrariamente una clave ya atestada: perder el registro del servidor puede requerir regenerar la clave y controlar el proceso de recuperación del cliente.

Añade HTTPS, límites de cuerpo HTTP y rate limiting por cliente en el proxy, autenticación/autorización y asociación de credenciales a la cuenta/sesión correspondiente. App Attest verifica la app/dispositivo, **no autentica usuarios**. Los límites en memoria no sustituyen protección contra abuso. La demo valida la cadena sin consultas de revocación ni evaluación de riesgo del receipt de Apple; no llama a APIs de Apple ni requiere claves privadas de desarrollador en el servidor.

## Pruebas

```sh
./mvnw test
```

Los tests criptográficos usan certificados sintéticos, no dispositivos ni servicios de Apple. Para comprobar el flujo completo hace falta una app firmada en un dispositivo físico compatible y una atestación real del entorno configurado.
