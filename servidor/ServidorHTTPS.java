package servidor;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import comun.ConfiguracionGoogle;
import comun.Protocolo;
import servidor.almacenamiento.AlmacenUsuarios;
import servidor.manejadores.ManejadorBajar;
import servidor.manejadores.ManejadorClavePublica;
import servidor.manejadores.ManejadorLogin;
import servidor.manejadores.ManejadorRegistro;
import servidor.manejadores.ManejadorSubir;
import servidor.seguridad.GestorTokens;
import servidor.seguridad.HashClaveLogin;
import servidor.seguridad.VerificadorGoogle;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.io.Console;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Base64;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Servidor de almacenamiento: com.sun.net.httpserver.HttpsServer (incluido en el JDK) solo con TLS 1.3 y el
 * certificado propio de servidor_secretos/servidor.p12. Registra los cinco endpoints de la guía.
 * La pimienta y el certificado se guardan en servidor_secretos, aparte de los datos de los usuarios.
 */
public class ServidorHTTPS {

    public static final int PUERTO_POR_DEFECTO = 8443;

    private final HttpsServer servidor;
    private final ExecutorService hilos = Executors.newFixedThreadPool(16);

    public ServidorHTTPS(int puerto, Path directorioDatos, SSLContext ssl, byte[] pimienta, Duration validezToken, VerificadorGoogle google) throws IOException {
        AlmacenUsuarios almacen = new AlmacenUsuarios(directorioDatos);
        GestorTokens tokens = new GestorTokens(validezToken);
        HashClaveLogin hash = new HashClaveLogin(pimienta);

        servidor = HttpsServer.create(new InetSocketAddress(puerto), 0);
        servidor.setHttpsConfigurator(new HttpsConfigurator(ssl) {
            @Override
            public void configure(HttpsParameters parametros) {
                SSLParameters ssl = getSSLContext().getDefaultSSLParameters();
                ssl.setProtocols(new String[]{"TLSv1.3"});   // solo TLS 1.3
                parametros.setSSLParameters(ssl);
            }
        });
        servidor.createContext(Protocolo.REGISTRO, new ManejadorRegistro(almacen, tokens, hash, google));
        servidor.createContext(Protocolo.LOGIN, new ManejadorLogin(almacen, tokens, hash, google));
        servidor.createContext(Protocolo.SUBIR, new ManejadorSubir(almacen, tokens));
        servidor.createContext(Protocolo.BAJAR, new ManejadorBajar(almacen, tokens));
        servidor.createContext(Protocolo.CLAVE_PUBLICA, new ManejadorClavePublica(almacen, tokens));
        servidor.setExecutor(hilos);
    }

    public void iniciar() {
        servidor.start();
    }

    public void parar() {
        servidor.stop(0);
        hilos.shutdownNow();
    }

    public int puerto() {
        return servidor.getAddress().getPort();
    }

    // Contexto TLS con el certificado y la clave privada del servidor (servidor.p12, creado con keytool)
    public static SSLContext contextoTLS(Path almacen, char[] claveAlmacen) throws IOException, GeneralSecurityException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(almacen)) {
            ks.load(in, claveAlmacen);
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
        kmf.init(ks, claveAlmacen);
        SSLContext ssl = SSLContext.getInstance("TLSv1.3");
        ssl.init(kmf.getKeyManagers(), null, null);
        return ssl;
    }

    // Contraseña del almacén del servidor: variable de entorno CYS_CLAVE_ALMACEN o se pregunta por consola.
    // No se guarda en el código ni en el repositorio.
    private static char[] claveAlmacen() throws IOException {
        String entorno = System.getenv("CYS_CLAVE_ALMACEN");
        if (entorno != null && !entorno.isEmpty()) {
            return entorno.toCharArray();
        }
        Console consola = System.console();
        if (consola != null) {
            return consola.readPassword("Contraseña del almacén servidor.p12: ");
        }
        System.out.print("Contraseña del almacén servidor.p12: ");
        return new java.io.BufferedReader(new java.io.InputStreamReader(System.in, StandardCharsets.UTF_8)).readLine().toCharArray();
    }

    // Pimienta: variable de entorno CYS_PIMIENTA (Base64) o servidor_secretos/pimienta.key; se crea la primera vez
    public static byte[] cargarPimienta(Path directorioSecretos) throws IOException {
        String entorno = System.getenv("CYS_PIMIENTA");
        if (entorno != null && !entorno.isBlank()) {
            return Base64.getDecoder().decode(entorno.trim());
        }
        Path fichero = directorioSecretos.resolve("pimienta.key");
        if (Files.isRegularFile(fichero)) {
            return Base64.getDecoder().decode(Files.readString(fichero, StandardCharsets.US_ASCII).trim());
        }
        Files.createDirectories(directorioSecretos);
        byte[] nueva = HashClaveLogin.nuevaPimienta();
        Files.writeString(fichero, Base64.getEncoder().encodeToString(nueva), StandardCharsets.US_ASCII);
        System.out.println("Pimienta nueva creada en " + fichero.toAbsolutePath() + " (sin ella los usuarios actuales no podrían entrar)");
        return nueva;
    }

    public static void main(String[] args) throws Exception {
        int puerto = args.length > 0 ? Integer.parseInt(args[0]) : PUERTO_POR_DEFECTO;
        Path datos = Path.of("servidor_datos");
        Path secretos = Path.of("servidor_secretos");
        ConfiguracionGoogle configuracion = ConfiguracionGoogle.cargar(ConfiguracionGoogle.ruta());
        VerificadorGoogle google = configuracion == null ? null : new VerificadorGoogle(configuracion);

        Path almacen = secretos.resolve("servidor.p12");
        if (!Files.isRegularFile(almacen)) {
            System.err.println("No existe " + almacen + ". Genera el certificado con ejecutar\\GenerarCertificado.bat");
            System.exit(1);
        }
        char[] clave = claveAlmacen();
        SSLContext ssl = contextoTLS(almacen, clave);
        java.util.Arrays.fill(clave, '\0');

        ServidorHTTPS servidor = new ServidorHTTPS(puerto, datos, ssl, cargarPimienta(secretos), GestorTokens.VALIDEZ_POR_DEFECTO, google);
        servidor.iniciar();
        System.out.println("Servidor HTTPS (TLS 1.3) escuchando en el puerto " + servidor.puerto());
        System.out.println("Datos de usuarios en " + datos.toAbsolutePath());
        System.out.println("Inicio con Google: " + (google == null ? "desactivado (no hay google_oauth.properties)" : "activado"));
        System.out.println("Pulsa Ctrl+C para pararlo.");
    }
}
