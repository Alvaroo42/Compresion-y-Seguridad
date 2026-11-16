package pruebas;

import cliente.criptografia.FirmaDigital.FirmaNoValidaException;
import cliente.google.CredencialGoogle;
import cliente.google.InicioGoogle;
import cliente.red.ClienteServidor;
import cliente.red.ClienteServidor.ErrorServidor;
import cliente.seguridad.DerivadorClaveContrasena;
import cliente.servicio.ServicioCifrado;
import cliente.servicio.ServicioCifrado.DetalleArchivo;
import cliente.servicio.SesionRemota;
import comun.ConfiguracionGoogle;
import servidor.ServidorHTTPS;
import servidor.seguridad.VerificadorGoogle;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.stream.Stream;

/**
 * Prueba de extremo a extremo: servidor HTTPS real y clientes reales en este proceso, siguiendo la checklist
 * del apartado 10 de la guía y las mejoras (firma digital, nombre cifrado y segundo factor con Google).
 * Uso: java -cp out;lib\bcprov.jar pruebas.PruebaExtremoAExtremo
 */
public class PruebaExtremoAExtremo {

    static final String CLAVE_ALMACEN = "clave-almacen-prueba";
    static final String CLAVE_CONFIANZA = "cys-confianza";
    static final Comprobaciones c = new Comprobaciones();

    public static void main(String[] args) {
        try {
            ejecutar();
        } catch (Throwable t) {
            t.printStackTrace();
            System.exit(2);
        }
    }

    static void ejecutar() throws Exception {
        Path base = Files.createTempDirectory("e2e-");
        Path secretos = base.resolve("servidor_secretos"), datos = base.resolve("servidor_datos"), confianza = base.resolve("cliente_confianza.p12");
        generarCertificado(secretos, confianza, "localhost");
        ProveedorGooglePrueba proveedor = new ProveedorGooglePrueba();
        ConfiguracionGoogle google = ConfiguracionGoogle.cargar(proveedor.escribirConfiguracion(base.resolve("google_oauth.properties")));
        ServidorHTTPS servidor = arrancar(datos, secretos, Duration.ofMinutes(30), google);
        String direccion = "localhost:" + servidor.puerto();
        System.out.println("Servidor de prueba en https://" + direccion);

        Path originales = Files.createDirectories(base.resolve("originales"));
        byte[] marca = "CONTENIDO-SECRETO-DE-LA-PRUEBA|".getBytes(StandardCharsets.UTF_8);
        Path informe = originales.resolve("informe confidencial ñ.txt");
        try (OutputStream out = Files.newOutputStream(informe)) {
            for (int i = 0; i < 5000; i++) {
                out.write(marca);
            }
        }
        Path foto = originales.resolve("foto-vacaciones.jpg");
        byte[] bytesFoto = new byte[3_000_000];
        new Random(7).nextBytes(bytesFoto);
        Files.write(foto, bytesFoto);

        // ================================================================== funcionalidad
        Comprobaciones.apartado("Registro, login, subir, compartir y descifrar (dos usuarios)");
        SesionRemota ana = sesion(direccion, confianza), luis = sesion(direccion, confianza);
        ana.registrar("ana", "clave-de-ana-2026".toCharArray(), null);
        luis.registrar("luis", "clave-de-luis-2026".toCharArray(), null);
        c.comprobar("/REGISTRO de ana y luis -> 201", true);
        Throwable t = Comprobaciones.excepcionDe(() -> sesion(direccion, confianza).registrar("ana", "otra-clave-larga".toCharArray(), null));
        c.comprobar("/REGISTRO de ana otra vez -> 409", esError(t, 409));
        t = Comprobaciones.excepcionDe(() -> sesion(direccion, confianza).registrar("pepe", "1234567".toCharArray(), null));
        c.comprobar("contraseña de menos de 8 caracteres rechazada en el cliente", t instanceof IllegalArgumentException);

        c.comprobar("login de ana: lista vacía", ana.iniciarSesion("ana", "clave-de-ana-2026".toCharArray(), null).isEmpty());
        DetalleArchivo dInforme = ana.cifrar(informe);
        DetalleArchivo dFoto = ana.cifrar(foto);
        Path salidaAna = base.resolve("descargas-ana");
        c.comprobar("ana descifra el informe (nombre con ñ): idéntico", resumen(ana.descifrar(dInforme, salidaAna)).equals(resumen(informe)));
        c.comprobar("descifrar otra vez no sobrescribe: " + ana.descifrar(dInforme, salidaAna).getFileName(),
                Files.exists(salidaAna.resolve("informe confidencial ñ (1).txt")));

        SesionRemota ana2 = sesion(direccion, confianza);
        List<DetalleArchivo> alEntrar = ana2.iniciarSesion("ana", "clave-de-ana-2026".toCharArray(), null);
        c.comprobar("al iniciar sesión se recuperan los archivos del servidor: " + alEntrar, alEntrar.size() == 2);

        ana.compartir(dFoto, "luis");
        List<DetalleArchivo> deLuis = luis.iniciarSesion("luis", "clave-de-luis-2026".toCharArray(), null);
        c.comprobar("luis ve la foto compartida: \"" + (deLuis.isEmpty() ? "" : deLuis.get(0)) + "\"",
                deLuis.size() == 1 && deLuis.get(0).emisor().equals("ana") && !deLuis.get(0).propio());
        c.comprobar("luis la descifra con SU privada: idéntica", resumen(luis.descifrar(deLuis.get(0), base.resolve("descargas-luis"))).equals(resumen(foto)));
        c.comprobar("luis no ve el informe que ana no ha compartido", deLuis.stream().noneMatch(d -> d.nombre().startsWith("informe")));
        t = Comprobaciones.excepcionDe(() -> ana.compartir(dInforme, "fantasma"));
        c.comprobar("compartir con un usuario que no existe -> 404", esError(t, 404));
        t = Comprobaciones.excepcionDe(() -> ana.compartir(dInforme, "ana"));
        c.comprobar("compartir con uno mismo -> rechazado", t instanceof IllegalArgumentException);

        // ================================================================== pruebas de la guía
        Comprobaciones.apartado("Login incorrecto: rechazado sin revelar si el usuario existe");
        Throwable malaClave = Comprobaciones.excepcionDe(() -> sesion(direccion, confianza).iniciarSesion("ana", "no-es-la-clave".toCharArray(), null));
        Throwable noExiste = Comprobaciones.excepcionDe(() -> sesion(direccion, confianza).iniciarSesion("nadie", "no-es-la-clave".toCharArray(), null));
        c.comprobar("contraseña incorrecta -> 401 \"" + malaClave.getMessage() + "\"", esError(malaClave, 401));
        c.comprobar("usuario inexistente -> 401 con el MISMO mensaje", esError(noExiste, 401) && malaClave.getMessage().equals(noExiste.getMessage()));
        long tExiste = tiempoLogin(direccion, confianza, "ana"), tNoExiste = tiempoLogin(direccion, confianza, "nadie");
        c.comprobar("y tarda lo mismo (" + tExiste + " ms con usuario real, " + tNoExiste + " ms sin él)", Math.abs(tExiste - tNoExiste) < Math.max(150, tExiste / 2));

        Comprobaciones.apartado("/SUBIR y /BAJAR protegidos con token");
        ClienteServidor red = new ClienteServidor(direccion, confianza, CLAVE_CONFIANZA.toCharArray());
        String tokenAna = red.login("ana", claveLogin("ana", "clave-de-ana-2026"), null, null).token();
        String tokenLuis = red.login("luis", claveLogin("luis", "clave-de-luis-2026"), null, null).token();
        Path tmp = base.resolve("bajado.cif");
        t = Comprobaciones.excepcionDe(() -> red.bajar(null, dInforme.id(), tmp));
        c.comprobar("/BAJAR sin token -> 401", esError(t, 401));
        t = Comprobaciones.excepcionDe(() -> red.bajar("token-inventado", dInforme.id(), tmp));
        c.comprobar("/BAJAR con token falso -> 401", esError(t, 401));
        t = Comprobaciones.excepcionDe(() -> red.subir(null, informe, "bm9tYnJl", new byte[256], null, null));
        c.comprobar("/SUBIR sin token -> 401", esError(t, 401));
        t = Comprobaciones.excepcionDe(() -> red.clavePublica(null, "luis"));
        c.comprobar("/CLAVE_PUBLICA sin token -> 401", esError(t, 401));
        t = Comprobaciones.excepcionDe(() -> red.bajar(tokenLuis, dInforme.id(), tmp));
        c.comprobar("luis pide el id de un archivo de ana -> 404", esError(t, 404));
        t = Comprobaciones.excepcionDe(() -> red.bajar(tokenLuis, "../ana/perfil.properties", tmp));
        c.comprobar("id con ruta maliciosa -> 404", esError(t, 404));
        red.bajar(tokenAna, dInforme.id(), tmp);
        c.comprobar("ana pide su propio archivo -> 200", Files.size(tmp) > 0);
        c.comprobar("/CLAVE_PUBLICA de luis -> clave RSA", red.clavePublica(tokenAna, "luis").length > 290);

        Comprobaciones.apartado("Token caducado");
        Path secretos2 = base.resolve("secretos_caducidad"), confianza2 = base.resolve("confianza_caducidad.p12");
        generarCertificado(secretos2, confianza2, "localhost");
        ServidorHTTPS corto = arrancar(base.resolve("datos_caducidad"), secretos2, Duration.ofSeconds(2), null);
        ClienteServidor redCorta = new ClienteServidor("localhost:" + corto.puerto(), confianza2, CLAVE_CONFIANZA.toCharArray());
        SesionRemota maria = sesion("localhost:" + corto.puerto(), confianza2);
        maria.registrar("maria", "clave-de-maria".toCharArray(), null);
        maria.iniciarSesion("maria", "clave-de-maria".toCharArray(), null);
        DetalleArchivo dMaria = maria.cifrar(informe);
        String tokenMaria = redCorta.login("maria", claveLogin("maria", "clave-de-maria"), null, null).token();
        redCorta.bajar(tokenMaria, dMaria.id(), tmp);
        c.comprobar("con el token vigente /BAJAR -> 200", true);
        Thread.sleep(2500);
        t = Comprobaciones.excepcionDe(() -> redCorta.bajar(tokenMaria, dMaria.id(), tmp));
        c.comprobar("pasada la caducidad /BAJAR -> 401", esError(t, 401));
        t = Comprobaciones.excepcionDe(() -> maria.cifrar(informe));
        c.comprobar("la aplicación también sabe que la sesión ha caducado", esError(t, 401));
        corto.parar();

        Comprobaciones.apartado("En el servidor no hay nada legible");
        List<String> prohibidos = List.of("CONTENIDO-SECRETO", "informe confidencial", "foto-vacaciones", "clave-de-ana-2026", "clave-de-luis-2026");
        List<String> encontrados = new ArrayList<>();
        int ficheros = 0;
        try (Stream<Path> todos = Files.walk(datos)) {
            for (Path p : todos.filter(Files::isRegularFile).toList()) {
                ficheros++;
                String texto = new String(Files.readAllBytes(p), StandardCharsets.ISO_8859_1);
                String decodificado = "";
                try {
                    decodificado = new String(Base64.getMimeDecoder().decode(texto.trim()), StandardCharsets.ISO_8859_1);
                } catch (IllegalArgumentException noEsBase64) {
                    // perfil y .meta no son Base64 enteros
                }
                for (String palabra : prohibidos) {
                    if (texto.contains(palabra) || decodificado.contains(palabra)) {
                        encontrados.add(p.getFileName() + ": " + palabra);
                    }
                }
            }
        }
        c.comprobar("revisados " + ficheros + " ficheros: ni contenidos, ni nombres de archivo, ni contraseñas " + encontrados, encontrados.isEmpty());
        Properties perfil = new Properties();
        try (InputStream in = Files.newInputStream(datos.resolve("usuarios/ana/perfil.properties"))) {
            perfil.load(in);
        }
        System.out.println("     perfil.properties de ana:");
        for (String clave : List.of("usuario", "algoritmo", "argon2.memoriaKiB", "argon2.iteraciones", "argon2.paralelismo", "salt", "hashLogin", "clavePublica", "clavePrivadaCifrada")) {
            String v = perfil.getProperty(clave);
            System.out.println("       " + clave + "=" + (v.length() > 48 ? v.substring(0, 48) + "..." : v));
        }
        String claveLoginAnaB64 = Base64.getEncoder().encodeToString(claveLogin("ana", "clave-de-ana-2026"));
        c.comprobar("el perfil guarda el hash Argon2id, su salt y sus parámetros, no la clave de login",
                "argon2id".equals(perfil.getProperty("algoritmo")) && "19456".equals(perfil.getProperty("argon2.memoriaKiB"))
                        && Base64.getDecoder().decode(perfil.getProperty("hashLogin")).length == 32 && !perfil.toString().contains(claveLoginAnaB64));
        byte[] privadaGuardada = Base64.getDecoder().decode(perfil.getProperty("clavePrivadaCifrada"));
        c.comprobar("la privada está cifrada (no empieza como una clave PKCS#8: 0x30 0x82)", !(privadaGuardada[0] == 0x30 && privadaGuardada[1] == (byte) 0x82));
        Path pimienta = secretos.resolve("pimienta.key");
        c.comprobar("la pimienta está en servidor_secretos, fuera de servidor_datos", Files.exists(pimienta) && !pimienta.startsWith(datos));
        c.comprobar("cada usuario tiene su carpeta (ana: 2 .cif, luis: 1 .cif)",
                contar(datos.resolve("usuarios/ana/archivos"), ".cif") == 2 && contar(datos.resolve("usuarios/luis/archivos"), ".cif") == 1);

        Comprobaciones.apartado("Canal TLS");
        try (SSLSocket s = (SSLSocket) contextoConfianza(confianza).getSocketFactory().createSocket("localhost", servidor.puerto())) {
            s.startHandshake();
            c.comprobar("protocolo negociado: " + s.getSession().getProtocol() + " / " + s.getSession().getCipherSuite(), "TLSv1.3".equals(s.getSession().getProtocol()));
        }
        t = Comprobaciones.excepcionDe(() -> {
            try (SSLSocket s = (SSLSocket) contextoConfianza(confianza).getSocketFactory().createSocket("localhost", servidor.puerto())) {
                s.setEnabledProtocols(new String[]{"TLSv1.2"});
                s.startHandshake();
            }
        });
        c.comprobar("un cliente con TLS 1.2 es rechazado", t != null);
        Path secretosFalsos = base.resolve("secretos_falsos"), confianzaFalsa = base.resolve("confianza_falsa.p12");
        generarCertificado(secretosFalsos, confianzaFalsa, "localhost");
        t = Comprobaciones.excepcionDe(() -> new ClienteServidor(direccion, confianzaFalsa, CLAVE_CONFIANZA.toCharArray()).login("ana", new byte[16], null, null));
        c.comprobar("un cliente que confía en OTRO certificado no se conecta (posible intermediario)", causa(t, SSLHandshakeException.class));
        t = Comprobaciones.excepcionDe(() -> new ClienteServidor("127.0.0.2:" + servidor.puerto(), confianza, CLAVE_CONFIANZA.toCharArray()).login("ana", new byte[16], null, null));
        c.comprobar("si el nombre del servidor no coincide con el del certificado, tampoco", t != null && !(t instanceof ErrorServidor));

        Comprobaciones.apartado("Tráfico capturado: va cifrado");
        byte[] captura = capturarTrafico(servidor.puerto(), confianza, originales);
        String capturaTexto = new String(captura, StandardCharsets.ISO_8859_1);
        c.comprobar("capturados " + captura.length + " bytes; empiezan con un registro TLS (0x16 0x03)", captura.length > 1000 && captura[0] == 0x16 && captura[1] == 0x03);
        c.comprobar("no se ve ni el usuario, ni la contraseña, ni el nombre del archivo, ni su contenido, ni el token",
                Stream.of("tomas", "contrasena-de-tomas", "nombre-secreto", "contenido-que-no-debe-verse", "Bearer", "POST /", "claveLogin")
                        .noneMatch(capturaTexto::contains));

        // ================================================================== mejoras
        Comprobaciones.apartado("Mejora: firma digital e integridad");
        Path cifEnServidor = datos.resolve("usuarios/ana/archivos/" + dInforme.id() + ".cif");
        byte[] original = Files.readAllBytes(cifEnServidor);
        byte[] alterado = original.clone();
        alterado[alterado.length / 2] = (byte) (alterado[alterado.length / 2] == 'A' ? 'B' : 'A');
        Files.write(cifEnServidor, alterado);
        t = Comprobaciones.excepcionDe(() -> ana.descifrar(dInforme, base.resolve("descargas-manipulado")));
        c.comprobar("si se cambia un byte del .cif en el servidor, la aplicación no lo descifra", t instanceof FirmaNoValidaException);
        System.out.println("     mensaje: " + (t == null ? "" : t.getMessage()));
        Files.write(cifEnServidor, original);
        c.comprobar("restaurado, se descifra bien", resumen(ana.descifrar(dInforme, base.resolve("descargas-restaurado"))).equals(resumen(informe)));
        Path metaLuis;
        try (Stream<Path> l = Files.list(datos.resolve("usuarios/luis/archivos"))) {
            metaLuis = l.filter(p -> p.toString().endsWith(".meta")).findFirst().orElseThrow();
        }
        String metaOriginal = Files.readString(metaLuis);
        Files.writeString(metaLuis, metaOriginal.replace("emisor=ana", "emisor=luis"));
        SesionRemota luis2 = sesion(direccion, confianza);
        DetalleArchivo suplantado = luis2.iniciarSesion("luis", "clave-de-luis-2026".toCharArray(), null).get(0);
        t = Comprobaciones.excepcionDe(() -> luis2.descifrar(suplantado, base.resolve("descargas-suplantado")));
        c.comprobar("si el servidor cambia el emisor (finge que lo envió otro), la firma no coincide", t instanceof FirmaNoValidaException);
        Files.writeString(metaLuis, metaOriginal);
        c.comprobar("el servidor no conoce los nombres: el .meta no contiene \"foto-vacaciones\"", !metaOriginal.contains("foto-vacaciones"));

        Comprobaciones.apartado("Mejora: segundo factor con Google");
        System.setProperty("cys.google.pista", "carol@gmail.com");
        CredencialGoogle gCarol = new InicioGoogle(google).iniciar(InicioGoogle::seguirSinNavegador);
        c.comprobar("inicio con Google (navegador -> código -> PKCE -> ID token): " + gCarol.correo(), gCarol.idToken().split("\\.").length == 3);
        SesionRemota carol = sesion(direccion, confianza);
        carol.registrar("carol", "clave-de-carol".toCharArray(), gCarol);
        c.comprobar("registro de carol protegido con Google -> 201", true);
        c.comprobar("entrar con la misma credencial justo después -> OK", carol.iniciarSesion("carol", "clave-de-carol".toCharArray(), gCarol).isEmpty()
                && "carol@gmail.com".equals(carol.getCorreoGoogle()));
        t = Comprobaciones.excepcionDe(() -> sesion(direccion, confianza).iniciarSesion("carol", "clave-de-carol".toCharArray(), null));
        c.comprobar("con la contraseña pero SIN Google -> 403 y la aplicación sabe que pide Google", esError(t, 403) && ((ErrorServidor) t).requiereGoogle());
        t = Comprobaciones.excepcionDe(() -> sesion(direccion, confianza).iniciarSesion("carol", "clave-que-no-es".toCharArray(), null));
        c.comprobar("con otra contraseña -> 401 genérico (no se revela que la cuenta usa Google)", esError(t, 401) && !((ErrorServidor) t).requiereGoogle());
        t = Comprobaciones.excepcionDe(() -> sesion(direccion, confianza).iniciarSesion("carol", "clave-de-carol".toCharArray(), gCarol));
        c.comprobar("reutilizar el mismo token de Google otra vez -> rechazado", esError(t, 401));
        CredencialGoogle gCarol2 = new InicioGoogle(google).iniciar(InicioGoogle::seguirSinNavegador);
        c.comprobar("con un inicio de Google nuevo -> entra", sesion(direccion, confianza).iniciarSesion("carol", "clave-de-carol".toCharArray(), gCarol2).isEmpty());
        System.setProperty("cys.google.pista", "intruso@gmail.com");
        CredencialGoogle gIntruso = new InicioGoogle(google).iniciar(InicioGoogle::seguirSinNavegador);
        t = Comprobaciones.excepcionDe(() -> sesion(direccion, confianza).iniciarSesion("carol", "clave-de-carol".toCharArray(), gIntruso));
        c.comprobar("contraseña robada + OTRA cuenta de Google -> 401 \"" + (t == null ? "" : t.getMessage()) + "\"", esError(t, 401));
        System.setProperty("cys.google.pista", "carol@gmail.com");
        CredencialGoogle gCarol3 = new InicioGoogle(google).iniciar(InicioGoogle::seguirSinNavegador);
        t = Comprobaciones.excepcionDe(() -> sesion(direccion, confianza).registrar("carol2", "clave-de-carol".toCharArray(), gCarol3));
        c.comprobar("la misma cuenta de Google no se puede registrar con otro usuario -> 409", esError(t, 409));
        c.comprobar("ana (sin Google) sigue entrando solo con contraseña", sesion(direccion, confianza).iniciarSesion("ana", "clave-de-ana-2026".toCharArray(), null).size() == 2);

        Comprobaciones.apartado("Mejora: tokens de Google falsificados que el servidor rechaza");
        VerificadorGoogle verificador = new VerificadorGoogle(google);
        Map<String, Object> bueno = proveedor.contenidoValido("dave@gmail.com", "nonce-1");
        c.comprobar("token correcto -> aceptado", Comprobaciones.excepcionDe(() -> verificador.verificar(proveedor.firmar(bueno), "nonce-1", "login")) == null);
        rechazado(verificador, "firmado con OTRA clave RSA", ProveedorGooglePrueba.firmar(bueno, "RS256", ProveedorGooglePrueba.KID, otraClave()), "nonce-1");
        rechazado(verificador, "sin firma (alg=none)", ProveedorGooglePrueba.firmar(bueno, "none", ProveedorGooglePrueba.KID, null), "nonce-1");
        String tokenBueno = proveedor.firmar(bueno);
        String[] partes = tokenBueno.split("\\.");
        Map<String, Object> cambiado = proveedor.contenidoValido("dave@gmail.com", "nonce-1");
        cambiado.put("sub", ProveedorGooglePrueba.subDe("carol@gmail.com"));
        String contenidoCambiado = Base64.getUrlEncoder().withoutPadding().encodeToString(ProveedorGooglePrueba.json(cambiado).getBytes(StandardCharsets.UTF_8));
        rechazado(verificador, "contenido cambiado (otro sub) con la firma original", partes[0] + "." + contenidoCambiado + "." + partes[2], "nonce-1");
        rechazado(verificador, "para otra aplicación (aud distinto)", conCampo(proveedor, "aud", "otra-app.apps.googleusercontent.com"), "nonce-1");
        rechazado(verificador, "de otro emisor (iss distinto)", conCampo(proveedor, "iss", "https://evil.example.com"), "nonce-1");
        long ahora = System.currentTimeMillis() / 1000;
        Map<String, Object> caducado = proveedor.contenidoValido("dave@gmail.com", "nonce-1");
        caducado.put("iat", ahora - 7200);
        caducado.put("exp", ahora - 3600);
        rechazado(verificador, "caducado", proveedor.firmar(caducado), "nonce-1");
        rechazado(verificador, "con otro nonce (de otro inicio de sesión)", proveedor.firmar(bueno), "nonce-distinto");
        rechazado(verificador, "con el correo sin verificar", conCampo(proveedor, "email_verified", Boolean.FALSE), "nonce-1");
        rechazado(verificador, "basura en vez de token", "esto.no.esunjwt", "nonce-1");

        Comprobaciones.apartado("Archivo grande (la memoria no crece con el tamaño)");
        Path video = originales.resolve("video.mp4");
        try (OutputStream out = Files.newOutputStream(video)) {
            byte[] bloque = new byte[1 << 20];
            Random r = new Random(3);
            for (int i = 0; i < 120; i++) {
                r.nextBytes(bloque);
                out.write(bloque);
            }
        }
        long t0 = System.nanoTime();
        DetalleArchivo dVideo = ana.cifrar(video);
        long t1 = System.nanoTime();
        Path videoDescifrado = ana.descifrar(dVideo, base.resolve("descargas-video"));
        long t2 = System.nanoTime();
        c.comprobar(String.format("120 MiB con %d MiB de memoria: cifrar+subir %.1f s, bajar+descifrar %.1f s, idéntico",
                Runtime.getRuntime().maxMemory() >> 20, (t1 - t0) / 1e9, (t2 - t1) / 1e9), resumen(videoDescifrado).equals(resumen(video)));

        Comprobaciones.apartado("Cerrar sesión");
        ana.close();
        t = Comprobaciones.excepcionDe(() -> ana.cifrar(informe));
        c.comprobar("tras cerrar sesión no queda ni token ni clave privada", t instanceof IllegalStateException);

        servidor.parar();
        proveedor.parar();
        c.terminar("Prueba de extremo a extremo");
    }

    // ------------------------------------------------------------------ utilidades

    static ServidorHTTPS arrancar(Path datos, Path secretos, Duration validez, ConfiguracionGoogle google) throws Exception {
        ServidorHTTPS s = new ServidorHTTPS(0, datos, ServidorHTTPS.contextoTLS(secretos.resolve("servidor.p12"), CLAVE_ALMACEN.toCharArray()),
                ServidorHTTPS.cargarPimienta(secretos), validez, google == null ? null : new VerificadorGoogle(google));
        s.iniciar();
        return s;
    }

    static SesionRemota sesion(String servidor, Path confianza) throws Exception {
        return new SesionRemota(new ServicioCifrado(new ClienteServidor(servidor, confianza, CLAVE_CONFIANZA.toCharArray())));
    }

    static byte[] claveLogin(String usuario, String contrasena) throws Exception {
        return DerivadorClaveContrasena.derivar(contrasena.toCharArray(), DerivadorClaveContrasena.saltDe(usuario)).login();
    }

    static long tiempoLogin(String servidor, Path confianza, String usuario) throws Exception {
        ClienteServidor red = new ClienteServidor(servidor, confianza, CLAVE_CONFIANZA.toCharArray());
        Comprobaciones.excepcionDe(() -> red.login(usuario, new byte[16], null, null));   // calentar
        long t0 = System.nanoTime();
        for (int i = 0; i < 3; i++) {
            Comprobaciones.excepcionDe(() -> red.login(usuario, new byte[16], null, null));
        }
        return (System.nanoTime() - t0) / 3_000_000;
    }

    static boolean esError(Throwable t, int estado) {
        return t instanceof ErrorServidor e && e.estado() == estado;
    }

    static boolean causa(Throwable t, Class<? extends Throwable> tipo) {
        for (Throwable x = t; x != null; x = x.getCause()) {
            if (tipo.isInstance(x)) {
                return true;
            }
        }
        return false;
    }

    static void rechazado(VerificadorGoogle verificador, String descripcion, String token, String nonce) {
        Throwable t = Comprobaciones.excepcionDe(() -> verificador.verificar(token, nonce, "login"));
        c.comprobar("token " + descripcion + " -> rechazado (" + (t == null ? "ACEPTADO" : t.getMessage()) + ")", t instanceof VerificadorGoogle.TokenNoValido);
    }

    static String conCampo(ProveedorGooglePrueba proveedor, String campo, Object valor) throws Exception {
        Map<String, Object> contenido = proveedor.contenidoValido("dave@gmail.com", "nonce-1");
        contenido.put(campo, valor);
        return proveedor.firmar(contenido);
    }

    static java.security.PrivateKey otraClave() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        return g.generateKeyPair().getPrivate();
    }

    static String resumen(Path p) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (InputStream in = Files.newInputStream(p)) {
            byte[] b = new byte[1 << 16];
            int n;
            while ((n = in.read(b)) > 0) {
                md.update(b, 0, n);
            }
        }
        return HexFormat.of().formatHex(md.digest());
    }

    static long contar(Path carpeta, String extension) throws IOException {
        try (Stream<Path> s = Files.list(carpeta)) {
            return s.filter(p -> p.toString().endsWith(extension)).count();
        }
    }

    // Lo que hace GenerarCertificado.bat (apartado 6.1 de la guía, opción A con keytool)
    static void generarCertificado(Path secretos, Path confianza, String cn) throws Exception {
        Files.createDirectories(secretos);
        Path p12 = secretos.resolve("servidor.p12"), crt = secretos.resolve("servidor.crt");
        keytool("-genkeypair", "-alias", "servidor", "-keyalg", "RSA", "-keysize", "2048", "-validity", "365", "-storetype", "PKCS12",
                "-keystore", p12.toString(), "-storepass", CLAVE_ALMACEN, "-dname", "CN=" + cn + ", OU=CyS, O=Universidad, C=ES",
                "-ext", "SAN=dns:localhost,ip:127.0.0.1");
        keytool("-exportcert", "-alias", "servidor", "-keystore", p12.toString(), "-storepass", CLAVE_ALMACEN, "-rfc", "-file", crt.toString());
        keytool("-importcert", "-alias", "servidor", "-file", crt.toString(), "-noprompt", "-storetype", "PKCS12",
                "-keystore", confianza.toString(), "-storepass", CLAVE_CONFIANZA);
    }

    static void keytool(String... argumentos) throws Exception {
        List<String> orden = new ArrayList<>();
        orden.add(Path.of(System.getProperty("java.home"), "bin", "keytool").toString());
        orden.addAll(List.of(argumentos));
        Process p = new ProcessBuilder(orden).redirectErrorStream(true).start();
        String salida = new String(p.getInputStream().readAllBytes());
        if (p.waitFor() != 0) {
            throw new IOException("keytool: " + salida);
        }
    }

    static SSLContext contextoConfianza(Path confianza) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(confianza)) {
            ks.load(in, CLAVE_CONFIANZA.toCharArray());
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        tmf.init(ks);
        SSLContext ssl = SSLContext.getInstance("TLS");
        ssl.init(null, tmf.getTrustManagers(), null);
        return ssl;
    }

    // Intermediario que reenvía bytes entre cliente y servidor y los guarda, como haría Wireshark
    static byte[] capturarTrafico(int puertoServidor, Path confianza, Path carpeta) throws Exception {
        ByteArrayOutputStream captura = new ByteArrayOutputStream();
        try (ServerSocket intermediario = new ServerSocket(0)) {
            Thread aceptar = new Thread(() -> {
                try {
                    while (true) {
                        Socket cliente = intermediario.accept();
                        Socket servidor = new Socket("localhost", puertoServidor);
                        bombear(cliente.getInputStream(), servidor.getOutputStream(), captura);
                        bombear(servidor.getInputStream(), cliente.getOutputStream(), captura);
                    }
                } catch (IOException e) {
                    // cerrado
                }
            });
            aceptar.setDaemon(true);
            aceptar.start();
            SesionRemota tomas = sesion("localhost:" + intermediario.getLocalPort(), confianza);
            tomas.registrar("tomas", "contrasena-de-tomas".toCharArray(), null);
            tomas.iniciarSesion("tomas", "contrasena-de-tomas".toCharArray(), null);
            Path secreto = carpeta.resolve("nombre-secreto.txt");
            Files.writeString(secreto, "contenido-que-no-debe-verse-en-la-red");
            DetalleArchivo d = tomas.cifrar(secreto);
            tomas.descifrar(d, carpeta.resolve("descargas-tomas"));
            tomas.close();
            Thread.sleep(300);
        }
        synchronized (captura) {
            return captura.toByteArray();
        }
    }

    static void bombear(InputStream in, OutputStream out, ByteArrayOutputStream captura) {
        Thread h = new Thread(() -> {
            byte[] b = new byte[8192];
            int n;
            try {
                while ((n = in.read(b)) != -1) {
                    synchronized (captura) {
                        captura.write(b, 0, n);
                    }
                    out.write(b, 0, n);
                    out.flush();
                }
            } catch (IOException e) {
                // cerrado
            }
        });
        h.setDaemon(true);
        h.start();
    }
}
