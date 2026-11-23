# Almacén seguro – Versión 2 (cliente-servidor cifrado)

Implementación de la «Guía de implementación — Versión 2» siguiendo su orden de trabajo (apartado 8.2), con
dos mejoras para la nota sacadas de la última diapositiva de la Fase II: **firma digital e integridad** de
los archivos y **nombre del archivo cifrado**.

El cliente hace todo el trabajo criptográfico; el servidor es un almacén con login: recibe bytes cifrados,
los guarda en la carpeta del usuario y los devuelve. Contraseña y clave de datos nunca salen del cliente.

## Cómo arrancarlo (Windows, Java 17 o superior)

1. `ejecutar\GenerarCertificado.bat` — una vez. keytool pide una contraseña para el almacén del servidor.
   Si los clientes van en otros PC, pasarle la IP del PC servidor (la «Dirección IPv4» de `ipconfig`):
   `GenerarCertificado.bat 10.163.179.48`, y copiar `cliente_confianza.p12` a la carpeta del proyecto de
   cada cliente. Si la IP cambia (otra red), hay que repetirlo.
2. `ejecutar\EjecutarServidor.bat` — pide la contraseña del almacén y escucha en el puerto 8443.
3. `ejecutar\EjecutarCliente.bat` — una vez por cada usuario que se quiera abrir a la vez.

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
| `cliente/interfaz/Interfaz.java` | cambia | + Compartir, + abrir tras descifrar, errores claros |
| `cliente/criptografia/FirmaDigital.java` | mejora | firma SHA3-256withRSA de cada archivo |
| `servidor/ServidorHTTPS.java` | nuevo | HttpsServer, TLS 1.3, carga servidor.p12 y la pimienta |
| `servidor/manejadores/Manejador*.java` | nuevo | /REGISTRO /LOGIN /SUBIR /BAJAR /CLAVE_PUBLICA |
| `servidor/seguridad/HashClaveLogin.java` | nuevo | PBKDF2-HMAC-SHA256 + salt + pimienta (incluido en Java) |
| `servidor/seguridad/GestorTokens.java` | nuevo | tokens de sesión de 30 min |
| `servidor/almacenamiento/AlmacenUsuarios.java` | nuevo | carpetas por usuario, perfil.properties, .cif y .meta |
| `comun/Protocolo.java` | nuevo | endpoints, cabeceras, campos y validación del usuario |
| `cliente/almacenamiento/GestorFicheros.java`, `SesionLocal.java` | borrado | su lógica pasa a `AlmacenUsuarios` y `SesionRemota` |

## Modelo criptográfico (notación del profesor)

- Contraseña p_u → H = SHA3-256(salt_u ‖ p_u), salt_u = SHA3-256("CyS-v2|" ‖ u)[0..15] (determinista).
- Clave de datos = H[0..15]: k_u* = E^{AES-GCM}_{H[0..15]}(k_u). **Nunca sale del cliente.**
- Clave de login = H[16..31]: el servidor guarda PBKDF2-HMAC-SHA256(HMAC-SHA256(pimienta, H[16..31]), salt aleatorio, 600 000 iteraciones).
- Archivo f: k_f aleatoria, c = Base64(IV ‖ E^{AES-CTR}_{k_f}(f)), k_f* = E^{RSA}_{K_u}(k_f).
- Compartir con v: k_f' = E^{RSA}_{K_v}(D^{RSA}_{k_u}(k_f*)). El archivo no se vuelve a cifrar.
- Mejora, firma: σ = S^{SHA3-256withRSA}_{k_emisor}("CyS-v2|firma|" ‖ k_f* ‖ nombre cifrado ‖ c).
- Mejora, nombre: nombre cifrado = Base64(IV ‖ E^{AES-CTR}_{k_f}(nombre)).

## Endpoints (apartado 5)

| Endpoint | Método | Protegido | Envía | Devuelve |
|---|---|---|---|---|
| /REGISTRO | POST | No | usuario, claveLogin, clavePublica, clavePrivadaCifrada | 201 · 409 |
| /LOGIN | POST | No | usuario, claveLogin | 200 token, pública, privada cifrada, archivos · 401 |
| /SUBIR | POST | Sí | cuerpo .cif; cabeceras Nombre, ClaveAESCifrada, Firma, Destinatario | 201 id |
| /BAJAR | GET | Sí | ?id= | 200 .cif · 404 si no es suyo |
| /CLAVE_PUBLICA | GET | Sí | ?usuario= | 200 · 404 |

Cuerpos de /REGISTRO y /LOGIN en formato `clave=valor` (Properties), binarios en Base64.
Token: 32 bytes de SecureRandom en Base64-URL, `Authorization: Bearer <token>`, 30 minutos.

## Checklist del apartado 10

| Requisito | Dónde |
|---|---|
| Toda la lógica y el cifrado en el cliente | `cliente/servicio`, `cliente/criptografia` |
| Archivos cifrados en una carpeta por usuario | `AlmacenUsuarios` |
| HTTPS (TLS 1.3) con certificado propio | `ServidorHTTPS`, `ClienteServidor` |
| Certificado con keytool, documentado | `GenerarCertificado.bat` |
| SHA3 partido: datos / login | `DerivadorClaveContrasena` |
| Clave de login ≠ clave de datos | `DerivadorClaveContrasena` |
| Hash lento (PBKDF2) con salt, parámetros y pimienta | `HashClaveLogin`, `ManejadorRegistro` |
| Privada subida cifrada con la clave de datos | `ProtectorClavePrivada` |
| /REGISTRO, /LOGIN, /SUBIR, /BAJAR, /CLAVE_PUBLICA | `servidor/manejadores` |
| Al entrar se recuperan los archivos | `ManejadorLogin`, `SesionRemota` |
| Compartir con el par propio y la pública del otro | `ServicioCifrado.compartirArchivo` |
| El archivo se abre al descifrarlo | `Interfaz.abrir` |
| Dos usuarios, subir y compartir | `ServicioCifrado`, `ManejadorSubir` |
| Contraseña incorrecta sin revelar si existe | `ManejadorLogin` (mismo mensaje y mismo tiempo) |
| /BAJAR sin token o caducado → 401 | `ManejadorBase.usuarioDelToken` |
| Id de otro usuario → 404 | `AlmacenUsuarios.rutaCif` |
| Nada legible en perfil.properties ni .cif | `AlmacenUsuarios` (solo guarda lo que llega cifrado) |
| Tráfico cifrado | `ServidorHTTPS`, `ClienteServidor` (TLS 1.3; se puede comprobar con Wireshark) |

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
- **Hash de la clave de login con PBKDF2-HMAC-SHA256** (600 000 iteraciones, las que recomienda OWASP) en lugar de
  Argon2id, scrypt o bcrypt: en Java esos tres necesitan una librería externa, y PBKDF2 viene incluido en el JDK.
  La pimienta se aplica antes como HMAC-SHA256(pimienta, claveLogin). PBKDF2 solo gasta CPU (no memoria), así que
  es algo más fácil de atacar con tarjetas gráficas que Argon2id; las iteraciones se guardan en el perfil para
  poder subirlas sin romper los usuarios existentes.

## Preguntas abiertas para el profesor (de la guía)

1. ¿Basta con un solo SHA3? Un SHA3 sin iteraciones se ataca rápido por fuerza bruta si alguien roba la privada
   cifrada del servidor. Si lo permite, solo cambia `DerivadorClaveContrasena.derivar()` (PBKDF2-HMAC-SHA256,
   600 000 iteraciones, partiendo los 32 bytes igual).

## Limitaciones conocidas (para el análisis de seguridad)

- Las claves públicas de los demás las da el servidor: un servidor malicioso podría dar una suya al compartir.
  La propia pública sí se comprueba contra la privada. La solución completa son certificados (tema 6).
- La misma pareja RSA cifra claves y firma (lo correcto sería una pareja para cada cosa).
- No hay límite de intentos de login (PBKDF2 lo encarece, pero no lo impide).
- Al compartir, el servidor guarda una copia del .cif en la carpeta del destinatario; no se puede «descompartir».
