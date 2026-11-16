package cliente.google;

import com.sun.net.httpserver.HttpServer;
import comun.ConfiguracionGoogle;
import comun.Json;

import java.awt.Desktop;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * Mejora: inicio de sesión con Google (OpenID Connect) para aplicaciones de escritorio, como recomienda Google:
 * 1. Se abre el navegador en la página de Google. La contraseña de Google se escribe allí, nunca en esta aplicación.
 * 2. Google devuelve un "código" a un mini servidor de esta aplicación en http://127.0.0.1:<puerto> (solo local).
 * 3. Se cambia el código por el ID token. Con PKCE: el cliente inventa un secreto (code_verifier), manda a Google
 *    solo su SHA-256 (code_challenge) y lo revela al canjear el código; quien robe el código no puede canjearlo.
 * El "state" evita que otra web nos cuele un código suyo y el "nonce" ata el token a este inicio de sesión.
 */
public class InicioGoogle {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Duration ESPERA_MAXIMA = Duration.ofMinutes(3);

    private final ConfiguracionGoogle configuracion;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

    public InicioGoogle(ConfiguracionGoogle configuracion) {
        this.configuracion = configuracion;
    }

    public CredencialGoogle iniciar(Consumer<URI> abrirNavegador) throws IOException, InterruptedException {
        String verificador = aleatorio(32);
        String reto = B64URL.encodeToString(sha256(verificador));
        String state = aleatorio(16);
        String nonce = aleatorio(16);

        CompletableFuture<String> codigo = new CompletableFuture<>();
        HttpServer local = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        local.createContext("/", ex -> {
            Map<String, String> p = parametros(ex.getRequestURI().getRawQuery());
            String mensaje;
            if (!state.equals(p.get("state"))) {
                mensaje = "Respuesta no válida.";
            } else if (p.containsKey("error")) {
                mensaje = "Has cancelado el inicio de sesión con Google. Puedes cerrar esta pestaña.";
                codigo.completeExceptionally(new IOException("Se ha cancelado el inicio de sesión con Google"));
            } else {
                mensaje = "Listo. Ya puedes cerrar esta pestaña y volver a Almacén seguro.";
                codigo.complete(p.get("code"));
            }
            byte[] html = ("<!doctype html><meta charset=utf-8><title>Almacén seguro</title>"
                    + "<body style='font-family:sans-serif;margin:3em'><h2>" + mensaje + "</h2></body>").getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
            ex.sendResponseHeaders(200, html.length);
            try (OutputStream out = ex.getResponseBody()) {
                out.write(html);
            }
        });
        local.start();
        try {
            String redireccion = "http://127.0.0.1:" + local.getAddress().getPort();
            Map<String, String> consulta = new LinkedHashMap<>();
            consulta.put("client_id", configuracion.clientId());
            consulta.put("redirect_uri", redireccion);
            consulta.put("response_type", "code");
            consulta.put("scope", "openid email");
            consulta.put("code_challenge", reto);
            consulta.put("code_challenge_method", "S256");
            consulta.put("state", state);
            consulta.put("nonce", nonce);
            consulta.put("prompt", "select_account");
            String pista = System.getProperty("cys.google.pista");   // solo para las pruebas automáticas
            if (pista != null) {
                consulta.put("login_hint", pista);
            }
            abrirNavegador.accept(URI.create(configuracion.authUri() + "?" + formulario(consulta)));

            String recibido;
            try {
                recibido = codigo.get(ESPERA_MAXIMA.toSeconds(), TimeUnit.SECONDS);
            } catch (TimeoutException e) {
                throw new IOException("No se ha completado el inicio de sesión con Google a tiempo");
            } catch (ExecutionException e) {
                throw new IOException(e.getCause().getMessage());
            }
            String idToken = canjear(recibido, redireccion, verificador);
            return new CredencialGoogle(idToken, nonce, correoDe(idToken));
        } finally {
            local.stop(0);
        }
    }

    // Cambia el código por los tokens en el servidor de Google (HTTPS con los certificados públicos de Java)
    private String canjear(String codigo, String redireccion, String verificador) throws IOException, InterruptedException {
        Map<String, String> datos = new LinkedHashMap<>();
        datos.put("code", codigo);
        datos.put("client_id", configuracion.clientId());
        datos.put("client_secret", configuracion.clientSecret());
        datos.put("redirect_uri", redireccion);
        datos.put("grant_type", "authorization_code");
        datos.put("code_verifier", verificador);
        HttpRequest peticion = HttpRequest.newBuilder(URI.create(configuracion.tokenUri()))
                .timeout(Duration.ofSeconds(20))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(formulario(datos)))
                .build();
        HttpResponse<String> respuesta = http.send(peticion, HttpResponse.BodyHandlers.ofString());
        Map<String, Object> json;
        try {
            json = Json.leerObjeto(respuesta.body());
        } catch (IllegalArgumentException e) {
            throw new IOException("Respuesta de Google no válida (HTTP " + respuesta.statusCode() + ")");
        }
        if (respuesta.statusCode() != 200 || !(json.get("id_token") instanceof String idToken)) {
            throw new IOException("Google no ha entregado el token: " + json.getOrDefault("error_description", json.get("error")));
        }
        return idToken;
    }

    // Abre la página de Google en el navegador del sistema
    public static void abrirEnNavegador(URI direccion) {
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(direccion);
            } else if (System.getProperty("os.name", "").startsWith("Windows")) {
                new ProcessBuilder("rundll32", "url.dll,FileProtocolHandler", direccion.toString()).start();
            } else {
                throw new IOException("no hay navegador");
            }
        } catch (IOException e) {
            throw new IllegalStateException("No se ha podido abrir el navegador. Abre esta dirección a mano:\n" + direccion, e);
        }
    }

    // Solo para las pruebas automáticas (-Dcys.google.navegador=http): hace lo mismo que el navegador
    // siguiendo la redirección, contra el proveedor de prueba local
    public static void seguirSinNavegador(URI direccion) {
        try {
            HttpClient cliente = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
            HttpResponse<Void> r = cliente.send(HttpRequest.newBuilder(direccion).GET().build(), HttpResponse.BodyHandlers.discarding());
            String destino = r.headers().firstValue("Location").orElseThrow(() -> new IOException("sin redirección"));
            cliente.send(HttpRequest.newBuilder(URI.create(destino)).GET().build(), HttpResponse.BodyHandlers.discarding());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    // Correo de la cuenta, solo para enseñarlo (quien comprueba la firma del token es el servidor)
    private static String correoDe(String idToken) {
        try {
            String contenido = new String(Base64.getUrlDecoder().decode(idToken.split("\\.")[1]), StandardCharsets.UTF_8);
            Object correo = Json.leerObjeto(contenido).get("email");
            return correo instanceof String c ? c : "";
        } catch (RuntimeException e) {
            return "";
        }
    }

    private static String aleatorio(int bytes) {
        byte[] b = new byte[bytes];
        RANDOM.nextBytes(b);
        return B64URL.encodeToString(b);
    }

    private static byte[] sha256(String texto) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(texto.getBytes(StandardCharsets.US_ASCII));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String formulario(Map<String, String> campos) {
        return campos.entrySet().stream()
                .map(c -> URLEncoder.encode(c.getKey(), StandardCharsets.UTF_8) + "=" + URLEncoder.encode(c.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
    }

    private static Map<String, String> parametros(String consulta) {
        Map<String, String> p = new HashMap<>();
        if (consulta != null) {
            for (String par : consulta.split("&")) {
                int igual = par.indexOf('=');
                if (igual > 0) {
                    p.put(URLDecoder.decode(par.substring(0, igual), StandardCharsets.UTF_8), URLDecoder.decode(par.substring(igual + 1), StandardCharsets.UTF_8));
                }
            }
        }
        return p;
    }
}
