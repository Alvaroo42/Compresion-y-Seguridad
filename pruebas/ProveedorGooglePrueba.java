package pruebas;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Proveedor de prueba que se comporta como Google para las pruebas automáticas (desde aquí no se puede iniciar
 * sesión en Google de verdad). Implementa lo mismo que usa la aplicación:
 *   /auth   página de autorización: redirige a http://127.0.0.1:<puerto>?code=...&state=...
 *   /token  canjea el código comprobando client_id, client_secret, redirect_uri y PKCE (S256)
 *   /certs  claves públicas en formato JWKS
 * y firma los ID token con RS256 y el mismo contenido que Google (iss, aud, sub, email, email_verified, iat,
 * exp, nonce). El servidor de la aplicación los comprueba con el mismo código que usa con Google.
 */
public class ProveedorGooglePrueba {

    public static final String CLIENT_ID = "cys-prueba.apps.googleusercontent.com";
    public static final String CLIENT_SECRET = "secreto-de-prueba";
    public static final String KID = "clave-prueba-1";

    private record Pendiente(String reto, String nonce, String redireccion, String correo) {
    }

    private final HttpServer servidor;
    private final KeyPair claves;
    private final Map<String, Pendiente> codigos = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();

    @SuppressWarnings("this-escape")
    public ProveedorGooglePrueba() throws Exception {
        KeyPairGenerator generador = KeyPairGenerator.getInstance("RSA");
        generador.initialize(2048);
        claves = generador.generateKeyPair();
        servidor = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        servidor.createContext("/auth", this::autorizar);
        servidor.createContext("/token", this::canjear);
        servidor.createContext("/certs", this::certificados);
        servidor.start();
    }

    public String base() {
        return "http://127.0.0.1:" + servidor.getAddress().getPort();
    }

    public void parar() {
        servidor.stop(0);
    }

    // google_oauth.properties apuntando a este proveedor
    public Path escribirConfiguracion(Path archivo) throws IOException {
        Files.writeString(archivo, "clientId=" + CLIENT_ID + "\nclientSecret=" + CLIENT_SECRET + "\nauthUri=" + base() + "/auth\ntokenUri="
                + base() + "/token\njwksUri=" + base() + "/certs\n");
        return archivo;
    }

    // Identificador fijo de la cuenta (como el "sub" de Google) a partir del correo
    public static String subDe(String correo) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(correo.getBytes(StandardCharsets.UTF_8));
            return "1" + new java.math.BigInteger(1, h).toString().substring(0, 20);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    // ------------------------------------------------------------------ tokens (también para pruebas negativas)

    public Map<String, Object> contenidoValido(String correo, String nonce) {
        long ahora = Instant.now().getEpochSecond();
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("iss", "https://accounts.google.com");
        c.put("azp", CLIENT_ID);
        c.put("aud", CLIENT_ID);
        c.put("sub", subDe(correo));
        c.put("email", correo);
        c.put("email_verified", Boolean.TRUE);
        c.put("nonce", nonce);
        c.put("iat", ahora);
        c.put("exp", ahora + 3600);
        return c;
    }

    public String firmar(Map<String, Object> contenido) throws Exception {
        return firmar(contenido, "RS256", KID, claves.getPrivate());
    }

    public static String firmar(Map<String, Object> contenido, String alg, String kid, PrivateKey clave) throws Exception {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        Map<String, Object> cabecera = new LinkedHashMap<>();
        cabecera.put("alg", alg);
        cabecera.put("kid", kid);
        cabecera.put("typ", "JWT");
        String datos = b64.encodeToString(json(cabecera).getBytes(StandardCharsets.UTF_8)) + "."
                + b64.encodeToString(json(contenido).getBytes(StandardCharsets.UTF_8));
        if (clave == null) {
            return datos + ".";
        }
        Signature firma = Signature.getInstance("SHA256withRSA");
        firma.initSign(clave);
        firma.update(datos.getBytes(StandardCharsets.US_ASCII));
        return datos + "." + b64.encodeToString(firma.sign());
    }

    // ------------------------------------------------------------------ endpoints

    private void autorizar(HttpExchange ex) throws IOException {
        Map<String, String> p = parametros(ex.getRequestURI().getRawQuery());
        String redireccion = p.getOrDefault("redirect_uri", "");
        if (!CLIENT_ID.equals(p.get("client_id")) || !redireccion.startsWith("http://127.0.0.1:") || !"code".equals(p.get("response_type"))
                || !p.getOrDefault("scope", "").contains("openid") || !"S256".equals(p.get("code_challenge_method"))
                || p.get("code_challenge") == null || p.get("state") == null || p.get("nonce") == null) {
            responder(ex, 400, "{\"error\":\"invalid_request\"}");
            return;
        }
        String codigo = aleatorio();
        codigos.put(codigo, new Pendiente(p.get("code_challenge"), p.get("nonce"), redireccion, p.getOrDefault("login_hint", "prueba@gmail.com")));
        ex.getResponseHeaders().set("Location", redireccion + "?state=" + URLEncoder.encode(p.get("state"), StandardCharsets.UTF_8)
                + "&code=" + codigo + "&scope=email+openid");
        ex.sendResponseHeaders(302, -1);
        ex.close();
    }

    private void canjear(HttpExchange ex) throws IOException {
        Map<String, String> p = parametros(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
        Pendiente pendiente = codigos.remove(p.getOrDefault("code", ""));   // cada código vale una sola vez
        try {
            String retoCalculado = Base64.getUrlEncoder().withoutPadding().encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(p.getOrDefault("code_verifier", "").getBytes(StandardCharsets.US_ASCII)));
            if (pendiente == null || !CLIENT_ID.equals(p.get("client_id")) || !CLIENT_SECRET.equals(p.get("client_secret"))
                    || !pendiente.redireccion().equals(p.get("redirect_uri")) || !"authorization_code".equals(p.get("grant_type"))
                    || !retoCalculado.equals(pendiente.reto())) {
                responder(ex, 400, "{\"error\":\"invalid_grant\",\"error_description\":\"Bad Request\"}");
                return;
            }
            String idToken = firmar(contenidoValido(pendiente.correo(), pendiente.nonce()));
            responder(ex, 200, "{\"access_token\":\"ya29.prueba\",\"expires_in\":3599,\"scope\":\"openid email\",\"token_type\":\"Bearer\",\"id_token\":\"" + idToken + "\"}");
        } catch (Exception e) {
            responder(ex, 500, "{\"error\":\"server_error\"}");
        }
    }

    private void certificados(HttpExchange ex) throws IOException {
        RSAPublicKey publica = (RSAPublicKey) claves.getPublic();
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        responder(ex, 200, "{\"keys\":[{\"kty\":\"RSA\",\"alg\":\"RS256\",\"use\":\"sig\",\"kid\":\"" + KID + "\",\"n\":\""
                + b64.encodeToString(sinCeroInicial(publica.getModulus().toByteArray())) + "\",\"e\":\""
                + b64.encodeToString(publica.getPublicExponent().toByteArray()) + "\"}]}");
    }

    // ------------------------------------------------------------------ utilidades

    private static byte[] sinCeroInicial(byte[] b) {
        return b.length > 1 && b[0] == 0 ? java.util.Arrays.copyOfRange(b, 1, b.length) : b;
    }

    private String aleatorio() {
        byte[] b = new byte[24];
        random.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private static void responder(HttpExchange ex, int estado, String json) throws IOException {
        byte[] cuerpo = json.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(estado, cuerpo.length);
        try (OutputStream out = ex.getResponseBody()) {
            out.write(cuerpo);
        }
    }

    private static Map<String, String> parametros(String texto) {
        Map<String, String> p = new HashMap<>();
        if (texto != null) {
            for (String par : texto.split("&")) {
                int igual = par.indexOf('=');
                if (igual > 0) {
                    p.put(URLDecoder.decode(par.substring(0, igual), StandardCharsets.UTF_8), URLDecoder.decode(par.substring(igual + 1), StandardCharsets.UTF_8));
                }
            }
        }
        return p;
    }

    static String json(Map<String, Object> mapa) {
        StringBuilder sb = new StringBuilder("{");
        for (Map.Entry<String, Object> e : mapa.entrySet()) {
            if (sb.length() > 1) {
                sb.append(',');
            }
            sb.append('"').append(e.getKey()).append("\":");
            Object v = e.getValue();
            sb.append(v instanceof String s ? "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"" : String.valueOf(v));
        }
        return sb.append('}').toString();
    }
}
