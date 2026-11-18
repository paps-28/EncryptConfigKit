# Crypto API demo: App Attest y Play Integrity

## Simulación local en emulador

La variante Android `devIntegritySimulation` y el perfil Maven/Spring `local-simulation` simulan Google para observar el happy path sin consolas. El perfil se compila en `target-simulation`, separado del backend normal, y exige escuchar exclusivamente en `127.0.0.1:18080`. Los veredictos de app reconocida, dispositivo íntegro y licencia son ficticios; se mantienen reales el challenge, su consumo, la comparación de requestHash y el cifrado RSA de la contraseña privada dev.

Con JDK 25 por proceso, ejecutar `scripts/run-local-simulation.ps1`. Lee únicamente la contraseña dev de la configuración privada de la host y la pasa al servidor por entorno; no la imprime ni la guarda en código. No utilizar ese perfil para un despliegue normal.

Conectar el emulador mediante `adb -s <serial> reverse tcp:18080 tcp:18080`. El APK de simulación apunta a esa dirección y emite tokens de prueba vinculados al hash. `GET /local-simulation/status` muestra sólo contadores de challenges, entregas y decodificaciones simuladas; permite comprobar que un segundo arranque no vuelve a consumir el backend.

La ejecución normal conserva el cliente real de Google. El perfil de simulación no forma parte de sus clases compiladas ni habilita un bypass en la ruta legacy.

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

El endpoint protegido acepta `publicKey` **solo como Base64 estándar de DER X.509 SubjectPublicKeyInfo**, con RSA de 2048–8192 bits y un máximo de 16 384 bytes DER. No acepta PEM, espacios, saltos de línea ni PKCS#1. El servicio RSA admite PEM/Base64 internamente, pero los endpoints legacy `/api/crypto/public-key` y `/api/crypto/public-key-with-file` devuelven `410` sin entregar material. Los endpoints protegidos de Apple y Android usan RSA-OAEP SHA-512 con MGF1 SHA-512 para el cifrado.

El endpoint protegido primero verifica el challenge, la assertion y su contador; solo después cifra la contraseña AES configurada en `APP_ATTEST_AES_KEY`. No utiliza una clave hardcodeada. La firma vincula **los mismos bytes DER originales** decodificados del Base64 y utilizados para cifrar la respuesta, no su representación textual. El backend replica exactamente el payload de Swift:

```text
clientDataHash = SHA256(UTF8("EncryptConfigKit.AppAttest.AESKey.v1") || 0x00 || challenge || rsaDER)
```

Se calcula `nonce = SHA256(authenticatorData || clientDataHash)` usando los bytes originales, incluidos los flags. Ese nonce de 32 bytes se verifica como **mensaje** con `SHA256withECDSA`, que aplica su propia capa SHA-256. No es equivalente a entregar directamente la concatenación al verificador ni a verificar el nonce como un digest sin hashear. No se utiliza fallback al cálculo anterior. También se comprueban el App ID y un contador uint32 estrictamente creciente. Cada entrega requiere un challenge y una assertion nuevos.

Este cálculo sigue los pasos de [Apple para verificar assertions](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server#Verify-the-assertion) y se contrasta con un vector público de [node-app-attest, revisión fijada](https://github.com/uebelack/node-app-attest/blob/f16c4bb71b737466872bc8b8a7dfd215364eaa83/test/verifyAssertion.test.js).

## Errores y límites

- `400`: Base64/CBOR/campos inválidos, challenge consumido, caducado o de otra clave/operación.
- `403`: prueba criptográfica inválida, identidad/entorno incorrectos o contador que no aumenta.
- `404`: clave no registrada al solicitar/verificar una assertion.
- `409`: clave ya registrada.
- `429`: límite de 10 000 challenges pendientes alcanzado.
- `503`: configuración de App Attest incompleta o almacén de 10 000 claves lleno.

Los challenges caducan a los cinco minutos y se consumen antes de verificar la prueba, incluso si esta falla. Solicita uno nuevo para reintentar. El consumo y la actualización de contadores son atómicos dentro de esta instancia. No se devuelve ningún secreto en los errores.

## Alcance de la demo y producción

`POST /api/crypto/public-key` y `/api/crypto/public-key-with-file` devuelven `410` y no entregan material. Coordinar el despliegue con las versiones Android que necesiten bootstrap.

El almacenamiento es en memoria y se pierde al reiniciar; no sirve para múltiples réplicas. Para producción necesitas persistencia compartida con consumo transaccional de challenges y comparación/actualización atómica de contadores. Apple no permite reatestar arbitrariamente una clave ya atestada: perder el registro del servidor puede requerir regenerar la clave y controlar el proceso de recuperación del cliente.

Añade HTTPS, límites de cuerpo HTTP y rate limiting por cliente en el proxy, autenticación/autorización y asociación de credenciales a la cuenta/sesión correspondiente. App Attest verifica la app/dispositivo, **no autentica usuarios**. Los límites en memoria no sustituyen protección contra abuso. La demo valida la cadena sin consultas de revocación ni evaluación de riesgo del receipt de Apple; no llama a APIs de Apple ni requiere claves privadas de desarrollador en el servidor.

## Pruebas

```sh
./mvnw test
```

Los tests criptográficos usan certificados sintéticos y un vector público de firma/assertion fijado en el repositorio; no llaman a dispositivos ni servicios de Apple. El vector externo permite detectar diferencias de hash que un generador y un verificador sintéticos podrían compartir por error. Para comprobar el flujo completo hace falta una app firmada en un dispositivo físico compatible y una atestación real del entorno configurado.

## Android: Play Integrity Standard

Configurar por despliegue:

- `PLAY_INTEGRITY_PACKAGE_NAME`: applicationId permitido.
- `PLAY_INTEGRITY_CERTIFICATE_SHA256`: digests SHA-256 de los certificados autorizados, en Base64 URL-safe como los devuelve Google, separados por comas. Incluir la firma de Play App Signing del canal elegido.
- `PLAY_INTEGRITY_PASSWORD_BASE64`: el mismo texto Base64 de `encryptConfig.password.<ambiente>`. Se envuelve sin decodificarlo; Android lo decodifica antes de SHA256/HKDF/AES-GCM. No cambia la derivación iOS.
- `PLAY_INTEGRITY_REQUESTS_PER_MINUTE`: límite global por instancia antes de llamar a Google; predeterminado 60. Las réplicas requieren limitación compartida y protección por origen en el proxy.
- Application Default Credentials del backend con permiso de Play Integrity y scope `https://www.googleapis.com/auth/playintegrity`. Preferir identidad de workload; nunca incorporar credenciales al APK ni al repositorio.

`POST /api/crypto/play-integrity/challenge` recibe `{}` y responde `challengeId`, `challenge` (32 bytes, Base64 estándar) y `expiresAt` (cinco minutos). El almacén compartido separa las operaciones Apple de Play. El reto se consume atómicamente antes de consultar Google; el siguiente intento necesita un reto y token nuevos incluso si se pierde la respuesta.

`POST /api/crypto/play-integrity/public-key` recibe exclusivamente `challengeId`, `publicKey` (SPKI DER RSA3072, exponente 65537, Base64 estándar sin PEM) e `integrityToken`. El servidor llama a `https://playintegrity.googleapis.com/v1/{paquete-configurado}:decodeIntegrityToken` y comprueba:

- requestHash = Base64 estándar con padding de SHA256(UTF8("EncryptConfigKit.AppAttest.AESKey.v1") || 0x00 || challengeBytes || rsaSpkiDer).
- Paquetes de request y app, certificados autorizados y `PLAY_RECOGNIZED`.
- Timestamp de hasta cinco minutos, tolerancia futura de 30 segundos.
- `MEETS_DEVICE_INTEGRITY` y `LICENSED`; no hay opción pública para omitir estas comprobaciones.

Sólo entonces responde `200 {"encryptedKey":"..."}`, con RSA-OAEP SHA512/MGF1 SHA512. Cuerpo de entrada y respuesta Google limitados a 64 KiB; token limitado a 32 KiB; HTTP sin redirects y con timeouts de diez segundos. No se incluyen cuerpos de Google en errores ni logs. Los tests sustituyen credenciales y transporte internamente; la ejecución normal siempre consulta Google.

La configuración ausente falla de forma controlada. Los retos, credenciales Apple y rate limit de esta demo son de una sola instancia, en RAM. Para producción se requiere estado compartido, persistencia Apple, TLS y controles de abuso en el ingreso.

## Fase externa pendiente

| Responsable | Acción y datos necesarios |
|---|---|
| Administrador Google Cloud / Play Console | Crear o seleccionar el proyecto por ambiente, habilitar Play Integrity API y vincularlo a la aplicación de Play Console. Confirmar cuota y acceso del backend. Entregar el número público de proyecto, no credenciales a Android. |
| Android | Configurar `encryptConfig.cloudProjectNumber.dev/qa/cert/prod` y `encryptConfig.url.dev/qa/cert/prod` en la configuración local/CI de cada ambiente. Confirmar applicationId, versión, certificado instalado y firma de Play App Signing. Preparar un canal de prueba reconocido y testers autorizados/licenciados. |
| Backend | Provisionar ADC con identidad de servidor y permiso de decodificación; configurar paquete, certificados y contraseña Base64 acordada con el build del mismo ambiente. Implementar HTTPS, estado compartido, límites de ingreso y observabilidad sin tokens, contraseñas ni cuerpos de Google. |
| Android + backend | Coordinar la retirada legacy con clientes antiguos y publicar una nueva versión del runtime sólo tras autorización. Verificar primero el flujo con respuesta real de Google en el canal elegido. |

La validación real debe comprobar instalación sin preferencias, challenge nuevo, token Standard aceptado, entrega RSA, apertura GCM del asset correcto y persistencia completa antes de login. El segundo arranque con preferencias completas debe funcionar sin red y sin preparar Integrity. Comprobar rechazo de app/firma/veredictos incorrectos y de prueba repetida, pérdida de respuesta, reintentos transitorios limitados y fallo sin navegación cuando falte material.

Un APK devDebug generado localmente puede ser rechazado por `PLAY_RECOGNIZED` o `LICENSED`; no se modifica la política para aceptarlo. Las respuestas de prueba configuradas en Play Console son pruebas controladas y deben separarse de una aceptación real de Google. La no afectación de iOS también requiere dispositivo Apple y prueba real de App Attest.

Referencias oficiales: [Standard](https://developer.android.com/google/play/integrity/standard), [setup](https://developer.android.com/google/play/integrity/setup), [veredictos](https://developer.android.com/google/play/integrity/verdicts), [ADC Java](https://docs.cloud.google.com/java/getting-started/getting-started-with-google-auth-library).
