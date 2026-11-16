package servidor.seguridad;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tokens de sesión. Si /LOGIN acierta se genera un token de 32 bytes aleatorios (SecureRandom, en Base64-URL)
 * que se guarda en memoria con su usuario y su caducidad (30 minutos). El cliente lo manda en cada petición
 * protegida (Authorization: Bearer <token>) y el servidor saca de él el usuario, nunca de un parámetro.
 */
public class GestorTokens {

    public static final Duration VALIDEZ_POR_DEFECTO = Duration.ofMinutes(30);
    private static final int TAM_TOKEN = 32;

    private record Sesion(String usuario, Instant caducidad) {
    }

    private final Map<String, Sesion> sesiones = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();
    private final Duration validez;

    public GestorTokens(Duration validez) {
        this.validez = validez;
    }

    public Duration validez() {
        return validez;
    }

    public String crear(String usuario) {
        borrarCaducados();
        byte[] bytes = new byte[TAM_TOKEN];
        random.nextBytes(bytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        sesiones.put(token, new Sesion(usuario, Instant.now().plus(validez)));
        return token;
    }

    // Usuario dueño del token, o null si el token no existe o ha caducado
    public String usuarioDe(String token) {
        if (token == null) {
            return null;
        }
        Sesion sesion = sesiones.get(token);
        if (sesion == null) {
            return null;
        }
        if (Instant.now().isAfter(sesion.caducidad())) {
            sesiones.remove(token);
            return null;
        }
        return sesion.usuario();
    }

    private void borrarCaducados() {
        Instant ahora = Instant.now();
        sesiones.values().removeIf(sesion -> ahora.isAfter(sesion.caducidad()));
    }
}
