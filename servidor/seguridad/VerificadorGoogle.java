package servidor.seguridad;

import comun.ConfiguracionGoogle;
import comun.Json;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Mejora: segundo factor con Google. Comprueba el "ID token" (un JWT) que Google entrega al cliente.
 * El token son tres partes en Base64-URL: cabecera.contenido.firma, y la firma es RSA con SHA-256 (RS256)
 * hecha con una clave privada de Google. El servidor la comprueba con las claves públicas que Google publica
 * (JWKS), descargadas por HTTPS. Además exige:
 *   iss = accounts.google.com          (lo ha emitido Google)
 *   aud = nuestro clientId             (es para esta aplicación y no para otra)
 *   exp en el futuro, iat reciente     (no está caducado ni es antiguo)
 *   nonce = el que generó el cliente   (es de este inicio de sesión y no de otro)
 *   email_verified = true
 * y que no se haya usado antes para lo mismo (un token copiado no sirve dos veces: vale una vez para
 * registrarse y una vez para entrar).
 * Si todo cuadra, el usuario es el "sub": el identificador fijo de la cuenta de Google.
 */
public class VerificadorGoogle {

    private static final Set<String> EMISORES = Set.of("https://accounts.google.com", "accounts.google.com");
    private static final Duration MARGEN_RELOJ = Duration.ofMinutes(1);
    private static final Duration ANTIGUEDAD_MAXIMA = Duration.ofMinutes(10);
    private static final Duration ESPERA_ENTRE_DESCARGAS = Duration.ofMinutes(1);

    // Identidad comprobada: identificador fijo de la cuenta de Google y su correo
    public record Identidad(String sub, String correo) {
    }

    public static class TokenNoValido extends Exception {
        private static final long serialVersionUID = 1L;

        public TokenNoValido(String motivo) {
            super(motivo);
        }
    }

    private final String clientId;
    private final URI jwks;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    private volatile Map<String, PublicKey> claves = Map.of();
    private volatile Instant ultimaDescarga = Instant.EPOCH;
    private final Map<String, Instant> usados = new ConcurrentHashMap<>();

    public VerificadorGoogle(ConfiguracionGoogle configuracion) {
        this.clientId = configuracion.clientId();
        this.jwks = URI.create(configuracion.jwksUri());
    }

    // uso = "registro" o "login"
    public Identidad verificar(String idToken, String nonceEsperado, String uso) throws TokenNoValido {
        String[] partes = idToken == null ? new String[0] : idToken.split("\\.", -1);
        if (partes.length != 3 || nonceEsperado == null || nonceEsperado.isBlank()) {
            throw new TokenNoValido("formato incorrecto");
        }
        Map<String, Object> cabecera = json(partes[0]);
        Map<String, Object> contenido = json(partes[1]);

        // 1) Firma: solo se acepta RS256 (nunca "none" ni algoritmos que el atacante elija)
        if (!"RS256".equals(cabecera.get("alg"))) {
            throw new TokenNoValido("algoritmo de firma no permitido: " + cabecera.get("alg"));
        }
        PublicKey clave = clavePublica(String.valueOf(cabecera.get("kid")));
        try {
            Signature firma = Signature.getInstance("SHA256withRSA");
            firma.initVerify(clave);
            firma.update((partes[0] + "." + partes[1]).getBytes(StandardCharsets.US_ASCII));
            if (!firma.verify(Base64.getUrlDecoder().decode(partes[2]))) {
                throw new TokenNoValido("la firma no es de Google");
            }
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new TokenNoValido("la firma no es de Google");
        }

        // 2) Contenido
        if (!EMISORES.contains(String.valueOf(contenido.get("iss")))) {
            throw new TokenNoValido("emisor incorrecto");
        }
        Object aud = contenido.get("aud");
        if (!(clientId.equals(aud) || (aud instanceof List<?> lista && lista.contains(clientId)))) {
            throw new TokenNoValido("el token es para otra aplicación");
        }
        Instant ahora = Instant.now();
        Instant exp = instante(contenido.get("exp"));
        Instant iat = instante(contenido.get("iat"));
        if (ahora.isAfter(exp.plus(MARGEN_RELOJ))) {
            throw new TokenNoValido("token caducado");
        }
        if (iat.isAfter(ahora.plus(MARGEN_RELOJ)) || ahora.isAfter(iat.plus(ANTIGUEDAD_MAXIMA))) {
            throw new TokenNoValido("token demasiado antiguo");
        }
        if (!nonceEsperado.equals(contenido.get("nonce"))) {
            throw new TokenNoValido("el nonce no coincide");
        }
        Object verificado = contenido.get("email_verified");
        if (!(Boolean.TRUE.equals(verificado) || "true".equals(verificado))) {
            throw new TokenNoValido("correo no verificado");
        }
        Object sub = contenido.get("sub");
        if (!(sub instanceof String s) || s.isEmpty() || s.length() > 255) {
            throw new TokenNoValido("falta el identificador de la cuenta");
        }

        // 3) Un solo uso por operación: el mismo token (misma cuenta y mismo nonce) no se acepta dos veces
        usados.values().removeIf(caduca -> ahora.isAfter(caduca.plus(MARGEN_RELOJ)));
        if (usados.putIfAbsent(s + "|" + nonceEsperado + "|" + uso, exp) != null) {
            throw new TokenNoValido("el token ya se ha usado");
        }
        Object correo = contenido.get("email");
        return new Identidad(s, correo instanceof String c ? c : "");
    }

    // Clave pública de Google con ese identificador (kid). Si no se conoce, se vuelven a descargar las claves:
    // Google las cambia cada pocos días.
    private PublicKey clavePublica(String kid) throws TokenNoValido {
        PublicKey clave = claves.get(kid);
        if (clave == null) {
            descargarClaves();
            clave = claves.get(kid);
        }
        if (clave == null) {
            throw new TokenNoValido("clave de firma desconocida");
        }
        return clave;
    }

    private synchronized void descargarClaves() throws TokenNoValido {
        if (Instant.now().isBefore(ultimaDescarga.plus(ESPERA_ENTRE_DESCARGAS)) && !claves.isEmpty()) {
            return;
        }
        try {
            HttpResponse<String> respuesta = http.send(HttpRequest.newBuilder(jwks).timeout(Duration.ofSeconds(10)).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            if (respuesta.statusCode() != 200) {
                throw new IOException("HTTP " + respuesta.statusCode());
            }
            Map<String, PublicKey> nuevas = new HashMap<>();
            Object lista = Json.leerObjeto(respuesta.body()).get("keys");
            if (lista instanceof List<?> elementos) {
                for (Object elemento : elementos) {
                    if (elemento instanceof Map<?, ?> jwk && "RSA".equals(jwk.get("kty")) && jwk.get("kid") instanceof String kid) {
                        BigInteger n = new BigInteger(1, Base64.getUrlDecoder().decode(String.valueOf(jwk.get("n"))));
                        BigInteger e = new BigInteger(1, Base64.getUrlDecoder().decode(String.valueOf(jwk.get("e"))));
                        nuevas.put(kid, KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e)));
                    }
                }
            }
            claves = Map.copyOf(nuevas);
            ultimaDescarga = Instant.now();
        } catch (IOException | GeneralSecurityException | IllegalArgumentException e) {
            throw new TokenNoValido("no se han podido descargar las claves de Google: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TokenNoValido("interrumpido");
        }
    }

    private static Map<String, Object> json(String parteBase64) throws TokenNoValido {
        try {
            return Json.leerObjeto(new String(Base64.getUrlDecoder().decode(parteBase64), StandardCharsets.UTF_8));
        } catch (IllegalArgumentException e) {
            throw new TokenNoValido("formato incorrecto");
        }
    }

    private static Instant instante(Object segundos) throws TokenNoValido {
        if (segundos instanceof Long s) {
            return Instant.ofEpochSecond(s);
        }
        throw new TokenNoValido("fechas incorrectas");
    }
}
