# encryptKeyTest: configuración de App Attest

La app consume los endpoints de App Attest mediante `AppAttestAPI` y `RemoteKeyProvider.shared`. `ContentView` carga la configuración cifrada usando ese proveedor, sin fallback al proveedor local ni al endpoint sin protección. `APIClient` lee la URL del `Info.plist`. Consulta también [el contrato del backend](../crypto-api-demo/README.md).

## Configuraciones de Xcode

Los siguientes build settings pertenecen al target **encryptKeyTest**, no a los targets de tests:

| Configuración | `APP_ATTEST_ENVIRONMENT` | `APP_ATTEST_API_BASE_URL` | Configuración cifrada |
| --- | --- | --- | --- |
| Debug | `development` | `http://localhost:8080` | `debug.xcconfig`: `CONFIG_ENV=dev`, `CONFIG_AES_KEY_DEV` |
| Beta | `production` | `https://localhost:8080` | `beta.xcconfig`: `CONFIG_ENV=qa`, `CONFIG_AES_KEY_QA` |
| Release | `production` | `https://localhost:8080` | Sin xcconfig asociado; configurar el cifrado de producción por separado |

Beta está pensada para **TestFlight**, que utiliza App Attest en producción aunque la configuración cifrada sea `qa`. No confundir el entorno del plugin (`dev`/`qa`) con el de App Attest (`development`/`production`). Antes de archivar, selecciona Beta o Release en la acción Archive del scheme según el destino.

Los valores se definen como literales en `encryptKeyTest.xcodeproj/project.pbxproj`, evitando que `//` de una URL se interprete como comentario de xcconfig. Los xcconfig existentes no se modifican. Para cambiar la URL, edita **Build Settings > User-Defined > APP_ATTEST_API_BASE_URL** en el target y configuración adecuados, o pásala a `xcodebuild`, por ejemplo `APP_ATTEST_API_BASE_URL=https://api.example.com`. Un valor añadido solo al xcconfig no prevalece sobre el valor del target. Si trasladas una URL a un xcconfig, usa una forma como `https:/$()/api.example.com`, no `https://api.example.com` sin escapar.

`Info.plist` expone:

- `AppAttestAPIBaseURL = $(APP_ATTEST_API_BASE_URL)`: URL base del servidor, sin el sufijo `/api/crypto/app-attest`.
- `AppAttestEnvironment = $(APP_ATTEST_ENVIRONMENT)`: `DeviceAppAttestProvider` lo utiliza junto con la URL del backend y el bundle identifier para separar el namespace de Keychain entre desarrollo y producción y entre servidores.

`encryptKeyTest/encryptKeyTest.entitlements` contiene `com.apple.developer.devicecheck.appattest-environment = $(APP_ATTEST_ENVIRONMENT)`. `CODE_SIGN_ENTITLEMENTS` se aplica **solo a `iphoneos*` e `iphonesimulator*`** en las tres configuraciones. No se añade este entitlement a macOS ni visionOS. El archivo está excluido del membership automático de recursos de la carpeta sincronizada: se usa para firmar, no se copia al bundle como recurso.

No se añade una entrada `SystemCapabilities` con un identificador interno no verificado. El entitlement declara la capacidad solicitada en la firma; también hay que autorizarla en el App ID y en el provisioning profile.

## Apple Developer y dispositivo físico

1. Abre `encryptKeyTest.xcodeproj` y selecciona el target de la app. La configuración actual usa **Automatically manage signing**, Team **`775YHCH8YG`** y bundle identifier **`com.encryptKeyTest`**. Usa una cuenta con acceso a ese equipo o ajusta ambos valores a los tuyos.
2. En Apple Developer > Certificates, Identifiers & Profiles, comprueba que el App ID explícito de ese bundle tiene habilitado **App Attest**. Regenera o deja que Xcode actualice los provisioning profiles tras habilitarlo. El entitlement local no sustituye la autorización del portal.
3. Para Debug, firma con un perfil de desarrollo compatible con `development`. Para Beta/TestFlight y Release, comprueba la firma de distribución y el entorno `production` del artefacto final; no des por válido un archive solo porque compila.
4. Ejecuta en un **iPhone/iPad físico compatible**, con acceso a los servicios de Apple y al backend. La implementación comprueba `DCAppAttestService.isSupported` y muestra un error si no está disponible. El simulador sirve para otras pruebas, **no valida una atestación real**, aunque tenga asociado el archivo de entitlements.
5. Inspecciona los entitlements del `.app` firmado (`codesign -d --entitlements :- /ruta/encryptKeyTest.app`) y su perfil (`security cms -D -i /ruta/encryptKeyTest.app/embedded.mobileprovision`). Verifica `application-identifier`, el App ID prefix y el entorno efectivo de App Attest, también en el artefacto de distribución. Comprueba además los valores expandidos del `Info.plist` del producto.

Referencia oficial del entitlement: [Apple: App Attest environment](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.devicecheck.appattest-environment).

## Identidad y clave del servidor

Configura en el entorno del **servidor** (sin añadir secretos a `Info.plist`):

- `APP_ATTEST_APP_ID=775YHCH8YG.com.encryptKeyTest`, **solo si** el App ID prefix real es `775YHCH8YG`. El prefix suele coincidir con el Team ID, pero no está garantizado; compruébalo en `application-identifier` del binario/perfil firmado. Si difiere, utiliza `<App ID prefix real>.com.encryptKeyTest`. No basta con mirar `DEVELOPMENT_TEAM`.
- `APP_ATTEST_ENVIRONMENT=development` para Debug o `production` para Beta/Release. Debe coincidir con el entitlement efectivo. Separa las instancias/configuraciones de servidor por entorno cuando sea necesario.
- `APP_ATTEST_AES_KEY`: texto Base64 de la misma clave AES usada por el plugin. En Debug debe coincidir con `CONFIG_AES_KEY_DEV` de `encryptKeyTest/resources/env-config/debug.xcconfig`; en Beta con `CONFIG_AES_KEY_QA` de `beta.xcconfig`. Las claves actuales son de demostración, no secretos de producción. Release no tiene xcconfig: revisa `encrypt-config.json`, los recursos y la clave del pipeline de producción antes de distribuir; esta preparación no completa ese pipeline.

Cambiar el entorno de App Attest no cambia automáticamente la clave AES ni el entorno de cifrado del plugin.

## Red local, HTTPS y ATS

`localhost` en el iPhone apunta **al iPhone**, no al Mac donde ejecutas el backend. Los valores por defecto son placeholders; reemplázalos por un hostname alcanzable desde el dispositivo, preferentemente **HTTPS con certificado válido y confiable**, por ejemplo `https://backend.example.com` o un hostname local con TLS correctamente configurado. Beta/Release no habilitan TLS en el backend por indicar `https`: necesitas un servidor/proxy que lo proporcione.

Se conserva `NSAllowsLocalNetworking = true` y se añade `NSLocalNetworkUsageDescription` para explicar el acceso al backend local. Acepta el permiso de red local en el dispositivo cuando corresponda. No se añade exploración Bonjour ni `NSBonjourServices`, porque esta configuración usa una URL directa.

Se elimina **`NSAllowsArbitraryLoads`**: ya no hay bypass global de ATS. Esto también puede afectar a conexiones HTTP existentes de la app. `NSAllowsLocalNetworking` no es una autorización universal de HTTP hacia cualquier destino ni evita la validación TLS. Una IP LAN con HTTP puede requerir una excepción ATS específica de **Debug**, según el sistema y el destino; esa excepción no se incluye aquí y debe evaluarse de forma acotada, sin volver a habilitar cargas arbitrarias para Beta/Release. Preferir HTTPS con hostname evita depender de excepciones para direcciones IP. No desactives la validación de certificados para resolver un certificado autofirmado.

## Flujo implementado

`AppAttestAPI` ejecuta este flujo y `RemoteKeyProvider.shared` agrupa las cargas concurrentes en una única tarea para no enviar assertions desordenadas:

1. Recuperar/crear el `keyId` de su namespace de Keychain (separado por entorno) y pedir primero un challenge con `purpose: "ASSERTION"` a `POST /api/crypto/app-attest/challenge`.
2. Si el servidor conoce la clave, generar la assertion y solicitar la clave AES con `POST /api/crypto/app-attest/public-key`.
3. Solo ante `404` de clave no registrada, pedir un challenge `ATTESTATION`, atestar y registrar en `POST /api/crypto/app-attest/attest`. Tras el registro, pedir un **nuevo** challenge `ASSERTION` y continuar por assertions.
4. Si el registro devuelve `409` (ya registrada, por ejemplo por concurrencia), usar la clave registrada: volver a solicitar un challenge `ASSERTION`, sin generar otra clave.
5. No rotar silenciosamente la clave ante errores. No tratar errores de red, `403` ni otros fallos como permiso para reatestar o regenerar. Los challenges son de un solo uso; cada nueva carga obtiene challenges nuevos. Se decodifica el challenge Base64 a bytes antes de pasarlo a App Attest. La assertion firma exactamente los bytes DER X.509 exportados con `RSAKeyManager.publicKeyBase64()`. La petición envía esos mismos bytes envueltos en PEM (`BEGIN PUBLIC KEY`) como `publicKey`, igual que el contrato original de `CryptoController`. El backend extrae los bytes DER originales con `RsaEncryptionService`, verifica la assertion y después cifra la contraseña AES con esa clave. La respuesta se descifra con RSA-OAEP SHA-512 y MGF1 SHA-512.

La app no imprime la configuración descifrada ni la clave AES. Muestra el estado de carga o el error y permite reintentar desde la pantalla. No se almacena una bandera local de «registrada»: se consulta el registro real del servidor antes de decidir si hace falta atestar, lo que también permite recuperar una respuesta de registro perdida cuando el servidor sí la procesó.

## Reinicios del backend y recuperación controlada

El backend de demo mantiene las claves públicas y contadores **en memoria**. Al reiniciarse pierde el registro, pero el cliente puede conservar un `keyId` que **ya fue atestado**. Un `404` en esa situación no implica que Apple permita volver a atestar esa misma clave: no es un proceso repetible arbitrariamente.

Para una demo controlada, y solo con intervención explícita, puede eliminarse manualmente la entrada exacta de Keychain que conserva el `keyId` en el namespace de esta app/entorno, reinicializar el estado asociado de la demo y generar una clave nueva para registrarla. No borrar todo el Keychain, no hacer esta recuperación automáticamente y no confiar en desinstalar/reinstalar: **la reinstalación no garantiza eliminar la entrada de Keychain**. No se incluye código ni herramienta de borrado en este cambio.

En producción se requiere persistencia de registros/contadores y un proceso explícito y autorizado de recuperación. App Attest no autentica al usuario ni sustituye autenticación/autorización. La validación end-to-end exige un dispositivo físico, firma/provisioning válidos, el entorno correcto y un backend accesible; los tests de simulador o con pruebas criptográficas sintéticas no sustituyen esa comprobación.

## Pruebas del cliente

`encryptKeyTestTests/AppAttestAPITests.swift` contiene siete tests con un proveedor simulado y `URLProtocol`, sin llamar a Apple ni al servidor real. Cubren clave registrada, registro tras `404` y respuesta `204`, conflicto `409`, errores `403`, challenges inválidos y envío de los bytes exactos de challenge/RSA. Ejecútalos desde el Test navigator de Xcode. No requieren soporte real de App Attest.

Durante esta implementación se compiló directamente el cliente para iOS arm64 y se ejecutaron los siete tests con XCTest en macOS: todos pasaron. También pasó el typecheck de la pantalla con un recurso generado existente. La compilación integral con `xcodebuild` quedó bloqueada por la versión desactualizada de CoreSimulator y permisos de caché del entorno; no se ha validado un archive firmado ni una atestación real.
