# Almacén seguro – Versión 2 (cliente-servidor cifrado)

Implementación de la «Guía de implementación — Versión 2» siguiendo su orden de trabajo (apartado 8.2), con
tres mejoras para la nota sacadas de la última diapositiva de la Fase II: **segundo factor con Google**,
**firma digital e integridad** de los archivos y **nombre del archivo cifrado**.

El cliente hace todo el trabajo criptográfico; el servidor es un almacén con login: recibe bytes cifrados,
los guarda en la carpeta del usuario y los devuelve. Contraseña y clave de datos nunca salen del cliente.

## Cómo arrancarlo (Windows, Java 17 o superior)

1. `ejecutar\GenerarCertificado.bat` — una vez. keytool pide una contraseña para el almacén del servidor.
   Si los clientes van en otros PC, pasarle la IP del PC servidor (la «Dirección IPv4» de `ipconfig`):
   `GenerarCertificado.bat 10.163.179.48`, y copiar `cliente_confianza.p12` a la carpeta del proyecto de
   cada cliente. Si la IP cambia (otra red), hay que repetirlo.
2. `ejecutar\EjecutarServidor.bat` — pide la contraseña del almacén y escucha en el puerto 8443.
3. `ejecutar\EjecutarCliente.bat` — una vez por cada usuario que se quiera abrir a la vez.
4. `ejecutar\EjecutarPruebas.bat` — pruebas automáticas (ver más abajo).

Para el inicio con Google, además, `google_oauth.properties` (ver «Configurar Google»).

## Qué hay en el proyecto (apartado 8.1 de la guía)

| Fichero | Estado | Qué hace |
|---|---|---|
| `cliente/codificacion/Codificador.java` | igual | Base64 en bloque y en flujo |
| `cliente/criptografia/CifradorAES.java` | igual | AES-128-CTR, IV aleatorio delante |
| `cliente/criptografia/CifradoRSA.java` | igual | RSA-2048, cifra la clave AES de cada archivo |
| `cliente/criptografia/ProtectorClavePrivada.java` | cambia | cifra la privada con la clave de datos, AES-GCM |
| `cliente/seguridad/DerivadorClaveContrasena.java` | cambia | `derivar()` → `ClavesDerivadas(datos, login)` |
| `cliente/red/ClienteServidor.java` | nuevo | HttpClient + TLS 1.3 + almacén de confianza, un método por endpoint |
| `cliente/servicio/ServicioCifrado.java` | cambia | mismo flujo, pero contra el servidor |
| `cliente/servicio/SesionRemota.java` | nuevo | antes SesionLocal: token y privada solo en memoria |
| `cliente/interfaz/Interfaz.java` | cambia | + Compartir, + abrir tras descifrar, + Google, errores claros |
| `cliente/criptografia/FirmaDigital.java` | mejora | firma SHA3-256withRSA de cada archivo |
| `cliente/google/InicioGoogle.java`, `CredencialGoogle.java` | mejora | OpenID Connect con PKCE (navegador + 127.0.0.1) |
| `servidor/ServidorHTTPS.java` | nuevo | HttpsServer, TLS 1.3, carga servidor.p12 y la pimienta |
| `servidor/manejadores/Manejador*.java` | nuevo | /REGISTRO /LOGIN /SUBIR /BAJAR /CLAVE_PUBLICA |
| `servidor/seguridad/HashClaveLogin.java` | nuevo | Argon2id + salt + pimienta (Bouncy Castle) |
| `servidor/seguridad/GestorTokens.java` | nuevo | tokens de sesión de 30 min |
| `servidor/seguridad/VerificadorGoogle.java` | mejora | comprueba la firma y el contenido del token de Google |
| `servidor/almacenamiento/AlmacenUsuarios.java` | nuevo | carpetas por usuario, perfil.properties, .cif y .meta |
| `comun/Protocolo.java` | nuevo | endpoints, cabeceras, campos y validación del usuario |
| `comun/Json.java`, `comun/ConfiguracionGoogle.java` | mejora | lector JSON mínimo y configuración de Google |
| `lib/bcprov.jar` | nuevo | Bouncy Castle 1.78.1 (solo el servidor, para Argon2id) |
| `pruebas/*.java` | nuevo | pruebas de cada paso y de extremo a extremo |
| `cliente/almacenamiento/GestorFicheros.java`, `SesionLocal.java` | borrado | su lógica pasa a `AlmacenUsuarios` y `SesionRemota` |

## Modelo criptográfico (notación del profesor)

- Contraseña p_u → H = SHA3-256(salt_u ‖ p_u), salt_u = SHA3-256("CyS-v2|" ‖ u)[0..15] (determinista).
- Clave de datos = H[0..15]: k_u* = E^{AES-GCM}_{H[0..15]}(k_u). **Nunca sale del cliente.**
- Clave de login = H[16..31]: el servidor guarda Argon2id(H[16..31], salt aleatorio, pimienta; 19456 KiB, 2, 1).
- Archivo f: k_f aleatoria, c = Base64(IV ‖ E^{AES-CTR}_{k_f}(f)), k_f* = E^{RSA}_{K_u}(k_f).
- Compartir con v: k_f' = E^{RSA}_{K_v}(D^{RSA}_{k_u}(k_f*)). El archivo no se vuelve a cifrar.
- Mejora, firma: σ = S^{SHA3-256withRSA}_{k_emisor}("CyS-v2|firma|" ‖ k_f* ‖ nombre cifrado ‖ c).
- Mejora, nombre: nombre cifrado = Base64(IV ‖ E^{AES-CTR}_{k_f}(nombre)).

## Endpoints (apartado 5)

| Endpoint | Método | Protegido | Envía | Devuelve |
|---|---|---|---|---|
| /REGISTRO | POST | No | usuario, claveLogin, clavePublica, clavePrivadaCifrada (+ idTokenGoogle, nonceGoogle) | 201 · 409 |
| /LOGIN | POST | No | usuario, claveLogin (+ idTokenGoogle, nonceGoogle) | 200 token, pública, privada cifrada, archivos · 401 · 403 si falta Google |
| /SUBIR | POST | Sí | cuerpo .cif; cabeceras Nombre, ClaveAESCifrada, Firma, Destinatario | 201 id |
| /BAJAR | GET | Sí | ?id= | 200 .cif · 404 si no es suyo |
| /CLAVE_PUBLICA | GET | Sí | ?usuario= | 200 · 404 |

Cuerpos de /REGISTRO y /LOGIN en formato `clave=valor` (Properties), binarios en Base64.
Token: 32 bytes de SecureRandom en Base64-URL, `Authorization: Bearer <token>`, 30 minutos.

## Checklist del apartado 10

| Requisito | Dónde | Prueba |
|---|---|---|
| Toda la lógica y el cifrado en el cliente | `cliente/servicio`, `cliente/criptografia` | e2e «nada legible» |
| Archivos cifrados en una carpeta por usuario | `AlmacenUsuarios` | paso 2, e2e |
| HTTPS (TLS 1.3) con certificado propio | `ServidorHTTPS`, `ClienteServidor` | e2e «Canal TLS», openssl |
| Certificado con keytool, documentado | `GenerarCertificado.bat` | paso 6 |
| SHA3 partido: datos / login | `DerivadorClaveContrasena` | paso 1 |
| Clave de login ≠ clave de datos | `DerivadorClaveContrasena` | paso 1 |
| Argon2id con salt, parámetros y pimienta | `HashClaveLogin`, `ManejadorRegistro` | paso 3, e2e |
| Privada subida cifrada con la clave de datos | `ProtectorClavePrivada` | paso 1, e2e |
| /REGISTRO, /LOGIN, /SUBIR, /BAJAR, /CLAVE_PUBLICA | `servidor/manejadores` | paso 4 (curl), e2e |
| Al entrar se recuperan los archivos | `ManejadorLogin`, `SesionRemota` | e2e |
| Compartir con el par propio y la pública del otro | `ServicioCifrado.compartirArchivo` | e2e, interfaz |
| El archivo se abre al descifrarlo | `Interfaz.abrir` | interfaz |
| Dos usuarios, subir y compartir | | e2e, interfaz |
| Contraseña incorrecta sin revelar si existe | `ManejadorLogin` (mismo mensaje y mismo tiempo) | e2e |
| /BAJAR sin token o caducado → 401 | `ManejadorBase.usuarioDelToken` | e2e |
| Id de otro usuario → 404 | `AlmacenUsuarios.rutaCif` | e2e |
| Nada legible en perfil.properties ni .cif | | e2e |
| Tráfico cifrado | | e2e (captura) — en Windows, también con Wireshark |

## Pruebas automáticas

`ejecutar\EjecutarPruebas.bat` ejecuta:

- `PruebaPaso1Claves` (15): misma contraseña → mismas dos claves, distintas entre sí; GCM detecta cambios.
- `PruebaPaso2Almacen` (34): carpetas, perfil, .cif/.meta, nombres de usuario peligrosos, rutas con `../`.
- `PruebaPaso3HashLogin` (8): Argon2id acepta la clave buena, rechaza la mala, la pimienta importa.
- `PruebaExtremoAExtremo` (63): servidor HTTPS real, la checklist entera, firma, Google y un vídeo de 120 MiB.

`PruebaPaso5Consola localhost:8443 cliente_confianza.p12` prueba un servidor ya arrancado desde la consola.

## Configurar Google (mejora: segundo factor)

Google demuestra **quién eres**, pero no puede guardar un secreto que el servidor no vea. Por eso la contraseña
sigue haciendo falta para la clave de datos (si no, el servidor podría descifrar la privada). Una cuenta
«registrada con Google» necesita las dos cosas para entrar: la contraseña **y** esa cuenta de Google. Una
contraseña robada no basta, y una sesión de Google robada tampoco.

1. Entrar en https://console.cloud.google.com con una cuenta de Gmail y crear un proyecto (por ejemplo «CyS»).
2. En «Google Auth Platform» (o «APIs y servicios → Pantalla de consentimiento de OAuth»): tipo **Externo**,
   nombre de la aplicación «Almacén seguro», correo de asistencia, y en **Audiencia / Usuarios de prueba**
   añadir los correos de Gmail que vayan a usarla (los cuatro del grupo y el del profesor).
   No hace falta verificar la aplicación: solo se piden `openid` y `email`.
3. En «Clientes» (o «Credenciales → Crear credenciales → ID de cliente de OAuth»): tipo **Aplicación de escritorio**.
4. Copiar el ID de cliente y el secreto en `google_oauth.properties` (hay una plantilla:
   `google_oauth.properties.ejemplo`) y poner ese fichero en la carpeta del proyecto del servidor y de cada cliente.
   **No se sube al repositorio.**
5. El servidor necesita Internet para descargar las claves públicas de Google
   (`https://www.googleapis.com/oauth2/v3/certs`), y cada cliente para abrir la página de Google.

En la aplicación: «Registrarse con Google» crea la cuenta y une tu cuenta de Google; después, «Entrar» pide la
contraseña y abre el navegador para confirmar con Google.

Las pruebas automáticas no usan Google de verdad: `pruebas/ProveedorGooglePrueba.java` se comporta como Google
(autorización, canje con PKCE, claves JWKS) y firma los tokens igual que Google, con RS256.

## Decisiones tomadas (para defenderlas)

- **Salt determinista** (opción 1 de la guía): no hace falta un endpoint /SALT que revelaría qué usuarios existen.
- **Privada con AES-GCM** (mejora recomendada por la guía): la etiqueta detecta si el servidor la modifica.
- **Contraseña mínima de 8 caracteres** (la guía recomienda subirla de 4 a 8).
- **Los id de archivo los genera el servidor** (UUID) y se devuelven en el 201 de /SUBIR.
- **El nombre de usuario** sigue el patrón `[A-Za-z0-9_.-]{3,32}` y además no puede empezar ni acabar en punto ni
  ser un nombre reservado de Windows (CON, NUL…), porque se usa como nombre de carpeta.
- **Contraseñas de los almacenes**: la del servidor (`servidor.p12`) no se guarda en ningún sitio, se pide al
  arrancar o se toma de `CYS_CLAVE_ALMACEN`. La del almacén de confianza del cliente no es secreta (solo contiene
  el certificado público del servidor, igual que el `cacerts` de Java usa `changeit`); por defecto `cys-confianza`
  o la variable `CYS_CLAVE_CONFIANZA`.
- **Login**: el mismo mensaje («Usuario o clave incorrectos») y el mismo tiempo exista o no el usuario.

## Preguntas abiertas para el profesor (de la guía)

1. ¿Basta con un solo SHA3? Un SHA3 sin iteraciones se ataca rápido por fuerza bruta si alguien roba la privada
   cifrada del servidor. Si lo permite, solo cambia `DerivadorClaveContrasena.derivar()` (PBKDF2-HMAC-SHA256,
   600 000 iteraciones, partiendo los 32 bytes igual).
2. ¿Se puede añadir el jar de Bouncy Castle (`lib/bcprov.jar`)? Si no, `HashClaveLogin` pasa a
   `PBKDF2WithHmacSHA256` del JDK con la pimienta aplicada antes como HMAC-SHA256(pimienta, claveLogin).

## Limitaciones conocidas (para el análisis de seguridad)

- Las claves públicas de los demás las da el servidor: un servidor malicioso podría dar una suya al compartir.
  La propia pública sí se comprueba contra la privada. La solución completa son certificados (tema 6).
- La misma pareja RSA cifra claves y firma (lo correcto sería una pareja para cada cosa).
- No hay límite de intentos de login (Argon2id lo encarece, pero no lo impide).
- Al compartir, el servidor guarda una copia del .cif en la carpeta del destinatario; no se puede «descompartir».
