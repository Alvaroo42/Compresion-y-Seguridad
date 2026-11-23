package cliente.red;

import comun.Protocolo;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Pattern;

/**
 * Comunicación con el servidor por HTTPS (java.net.http.HttpClient, TLS 1.3). Un método por endpoint.
 * Aquí no se cifra nada: los datos ya llegan cifrados desde ServicioCifrado. El cliente confía SOLO en el
 * certificado del servidor guardado en cliente_confianza.p12; nunca se acepta cualquier certificado ni se
 * desactiva la comprobación del nombre del servidor.
 */
public class ClienteServidor {

    private static final Pattern DIRECCION = Pattern.compile("[A-Za-z0-9.-]+(:[0-9]{1,5})?");
    private static final Base64.Encoder B64 = Base64.getEncoder();

    // Tiempos de espera. Entre dos PC (o por una Wi-Fi compartida desde el móvil) la conexión y la primera
    // negociación TLS pueden tardar bastante más que en local, así que se deja margen. La espera para conectar
    // se puede cambiar con -Dcys.espera=<segundos>.
    private static final Duration ESPERA_CONEXION = Duration.ofSeconds(Long.getLong("cys.espera", 60));
    private static final Duration ESPERA_RESPUESTA = Duration.ofSeconds(120);
    private static final Base64.Decoder DE_B64 = Base64.getDecoder();

    // Error devuelto por el servidor: código HTTP y su mensaje
    public static class ErrorServidor extends IOException {
        private static final long serialVersionUID = 1L;
        private final int estado;
        private final boolean requiereGoogle;

        public ErrorServidor(int estado, String mensaje, boolean requiereGoogle) {
            super(mensaje);
            this.estado = estado;
            this.requiereGoogle = requiereGoogle;
        }

        public int estado() {
            return estado;
        }

        public boolean requiereGoogle() {
            return requiereGoogle;
        }
    }

    // Un archivo de la lista de /LOGIN (solo metadatos; el contenido se pide con /BAJAR)
    public record ArchivoRemoto(String id, String nombreCifrado, byte[] claveAESCifrada, String emisor, byte[] firma) {
    }

    public record RespuestaLogin(String token, long validezSegundos, byte[] clavePublica, byte[] clavePrivadaCifrada,
                                 String correoGoogle, List<ArchivoRemoto> archivos) {
    }

    private final HttpClient http;
    private final String base;

    // servidor = "nombre:puerto" (por ejemplo localhost:8443)
    public ClienteServidor(String servidor, Path almacenConfianza, char[] claveConfianza) throws IOException, GeneralSecurityException {
        if (servidor == null || !DIRECCION.matcher(servidor).matches()) {
            throw new IllegalArgumentException("Dirección del servidor no válida (ejemplo: localhost:8443)");
        }
        this.base = "https://" + servidor;

        KeyStore confianza = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(almacenConfianza)) {
            confianza.load(in, claveConfianza);
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        tmf.init(confianza);
        SSLContext ssl = SSLContext.getInstance("TLSv1.3");
        ssl.init(null, tmf.getTrustManagers(), null);

        this.http = HttpClient.newBuilder()
                .sslContext(ssl)
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(ESPERA_CONEXION)
                .build();
    }

    // POST /REGISTRO: usuario, claveLogin, clavePublica, clavePrivadaCifrada (+ token de Google si se usa)
    public void registrar(String usuario, byte[] claveLogin, byte[] clavePublica, byte[] clavePrivadaCifrada,
                          String idTokenGoogle, String nonceGoogle) throws IOException {
        Map<String, String> campos = new LinkedHashMap<>();
        campos.put(Protocolo.CAMPO_USUARIO, usuario);
        campos.put(Protocolo.CAMPO_CLAVE_LOGIN, B64.encodeToString(claveLogin));
        campos.put(Protocolo.CAMPO_CLAVE_PUBLICA, B64.encodeToString(clavePublica));
        campos.put(Protocolo.CAMPO_CLAVE_PRIVADA_CIFRADA, B64.encodeToString(clavePrivadaCifrada));
        anadirGoogle(campos, idTokenGoogle, nonceGoogle);
        exigir(enviar(peticion(Protocolo.REGISTRO, null).POST(cuerpo(campos)).build()), 201);
    }

    // POST /LOGIN: usuario y claveLogin. Devuelve token, pública, privada cifrada y la lista de archivos
    public RespuestaLogin login(String usuario, byte[] claveLogin, String idTokenGoogle, String nonceGoogle) throws IOException {
        Map<String, String> campos = new LinkedHashMap<>();
        campos.put(Protocolo.CAMPO_USUARIO, usuario);
        campos.put(Protocolo.CAMPO_CLAVE_LOGIN, B64.encodeToString(claveLogin));
        anadirGoogle(campos, idTokenGoogle, nonceGoogle);
        HttpResponse<byte[]> respuesta = exigir(enviar(peticion(Protocolo.LOGIN, null).POST(cuerpo(campos)).build()), 200);

        Properties datos = Protocolo.leer(new String(respuesta.body(), StandardCharsets.UTF_8));
        List<ArchivoRemoto> archivos = new ArrayList<>();
        int total = Integer.parseInt(datos.getProperty(Protocolo.CAMPO_ARCHIVOS, "0"));
        for (int i = 0; i < total; i++) {
            String prefijo = Protocolo.PREFIJO_ARCHIVO + i;
            String firma = datos.getProperty(prefijo + Protocolo.SUFIJO_FIRMA);
            archivos.add(new ArchivoRemoto(datos.getProperty(prefijo + Protocolo.SUFIJO_ID),
                    datos.getProperty(prefijo + Protocolo.SUFIJO_NOMBRE),
                    DE_B64.decode(datos.getProperty(prefijo + Protocolo.SUFIJO_CLAVE_AES)),
                    datos.getProperty(prefijo + Protocolo.SUFIJO_EMISOR),
                    firma == null ? null : DE_B64.decode(firma)));
        }
        return new RespuestaLogin(datos.getProperty(Protocolo.CAMPO_TOKEN),
                Long.parseLong(datos.getProperty(Protocolo.CAMPO_VALIDEZ_TOKEN, "1800")),
                DE_B64.decode(datos.getProperty(Protocolo.CAMPO_CLAVE_PUBLICA)),
                DE_B64.decode(datos.getProperty(Protocolo.CAMPO_CLAVE_PRIVADA_CIFRADA)),
                datos.getProperty(Protocolo.CAMPO_CORREO_GOOGLE), archivos);
    }

    // POST /SUBIR: cuerpo = bytes del .cif; cabeceras Nombre, ClaveAESCifrada, Firma y Destinatario (opcional)
    public String subir(String token, Path cif, String nombreCifrado, byte[] claveAESCifrada, byte[] firma, String destinatario) throws IOException {
        HttpRequest.Builder peticion = peticion(Protocolo.SUBIR, token)
                .header(Protocolo.CABECERA_NOMBRE, nombreCifrado)
                .header(Protocolo.CABECERA_CLAVE_AES, B64.encodeToString(claveAESCifrada))
                .header("Content-Type", "application/octet-stream")
                .timeout(Duration.ofHours(2))
                .POST(HttpRequest.BodyPublishers.ofFile(cif));
        if (firma != null) {
            peticion.header(Protocolo.CABECERA_FIRMA, B64.encodeToString(firma));
        }
        if (destinatario != null) {
            peticion.header(Protocolo.CABECERA_DESTINATARIO, destinatario);
        }
        return new String(exigir(enviar(peticion.build()), 201).body(), StandardCharsets.UTF_8).trim();
    }

    // GET /BAJAR?id=<id>: guarda el .cif en 'destino' sin cargarlo entero en memoria
    public void bajar(String token, String id, Path destino) throws IOException {
        HttpRequest peticion = peticion(Protocolo.BAJAR + "?" + Protocolo.PARAM_ID + "=" + codificar(id), token)
                .timeout(Duration.ofHours(2)).GET().build();
        try {
            HttpResponse<InputStream> respuesta = http.send(peticion, HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream in = respuesta.body()) {
                if (respuesta.statusCode() != 200) {
                    throw new ErrorServidor(respuesta.statusCode(), new String(in.readNBytes(1024), StandardCharsets.UTF_8).trim(), false);
                }
                Files.copy(in, destino, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Operación interrumpida", e);
        }
    }

    // GET /CLAVE_PUBLICA?usuario=<usuario>: clave pública (X.509) de otro usuario
    public byte[] clavePublica(String token, String usuario) throws IOException {
        HttpRequest peticion = peticion(Protocolo.CLAVE_PUBLICA + "?" + Protocolo.PARAM_USUARIO + "=" + codificar(usuario), token).GET().build();
        return DE_B64.decode(new String(exigir(enviar(peticion), 200).body(), StandardCharsets.UTF_8).trim());
    }

    // ------------------------------------------------------------------ utilidades

    private HttpRequest.Builder peticion(String ruta, String token) {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + ruta)).timeout(ESPERA_RESPUESTA);
        if (token != null) {
            b.header(Protocolo.CABECERA_AUTORIZACION, Protocolo.PREFIJO_BEARER + token);
        }
        return b;
    }

    private static HttpRequest.BodyPublisher cuerpo(Map<String, String> campos) {
        return HttpRequest.BodyPublishers.ofString(Protocolo.escribir(campos), StandardCharsets.UTF_8);
    }

    private static void anadirGoogle(Map<String, String> campos, String idToken, String nonce) {
        if (idToken != null) {
            campos.put(Protocolo.CAMPO_ID_TOKEN_GOOGLE, idToken);
            campos.put(Protocolo.CAMPO_NONCE_GOOGLE, nonce);
        }
    }

    private HttpResponse<byte[]> enviar(HttpRequest peticion) throws IOException {
        try {
            return http.send(peticion, HttpResponse.BodyHandlers.ofByteArray());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Operación interrumpida", e);
        }
    }

    private static HttpResponse<byte[]> exigir(HttpResponse<byte[]> respuesta, int esperado) throws ErrorServidor {
        if (respuesta.statusCode() != esperado) {
            boolean google = respuesta.headers().firstValue(Protocolo.CABECERA_REQUIERE_GOOGLE).isPresent();
            throw new ErrorServidor(respuesta.statusCode(), new String(respuesta.body(), StandardCharsets.UTF_8).trim(), google);
        }
        return respuesta;
    }

    private static String codificar(String valor) {
        return URLEncoder.encode(valor == null ? "" : valor, StandardCharsets.UTF_8);
    }
}
