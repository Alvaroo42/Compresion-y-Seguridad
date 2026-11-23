package servidor.seguridad;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * El servidor recibe la clave de login (16 bytes) y la vuelve a resumir con PBKDF2, un algoritmo lento a
 * propósito: si alguien roba la carpeta de datos, no puede usar los hashes para entrar y probar contraseñas
 * le sale muy caro.
 *   hashLogin = PBKDF2-HMAC-SHA256(HMAC-SHA256(pimienta, claveLogin), salt, iteraciones)
 * - pimienta: secreto de 32 bytes común a todo el servidor, guardado FUERA de servidor_datos. Se aplica antes
 *   con HMAC-SHA256: sin ella, los hashes robados no sirven para nada.
 * - salt: 16 bytes aleatorios por usuario, guardados en su perfil.
 * - iteraciones: el coste. Se guardan junto al hash para poder subirlas más adelante sin romper los usuarios
 *   antiguos.
 * Todo viene incluido en Java (PBKDF2WithHmacSHA256 y HmacSHA256): no hace falta ninguna librería externa.
 */
public class HashClaveLogin {

    public static final String ALGORITMO = "pbkdf2-sha256";
    public static final int TAM_SALT = 16;
    public static final int TAM_HASH = 32;
    public static final int TAM_PIMIENTA = 32;

    // Coste de PBKDF2-HMAC-SHA256. El recomendado por OWASP: 600 000 iteraciones
    public record Parametros(int iteraciones) {
    }

    public static final Parametros RECOMENDADOS = new Parametros(600_000);

    private static final SecureRandom RANDOM = new SecureRandom();
    private final byte[] pimienta;
    private final byte[] saltFalso = nuevoSalt();

    public HashClaveLogin(byte[] pimienta) {
        if (pimienta == null || pimienta.length != TAM_PIMIENTA) {
            throw new IllegalArgumentException("La pimienta debe tener " + TAM_PIMIENTA + " bytes");
        }
        this.pimienta = pimienta.clone();
    }

    public static byte[] nuevoSalt() {
        byte[] salt = new byte[TAM_SALT];
        RANDOM.nextBytes(salt);
        return salt;
    }

    public static byte[] nuevaPimienta() {
        byte[] pimienta = new byte[TAM_PIMIENTA];
        RANDOM.nextBytes(pimienta);
        return pimienta;
    }

    // 1) HMAC-SHA256 con la pimienta como clave. 2) PBKDF2 con el salt del usuario.
    // PBKDF2 de Java recibe la contraseña como char[], así que el resultado del HMAC (bytes) se le pasa en Base64.
    public byte[] calcular(byte[] claveLogin, byte[] salt, Parametros p) {
        byte[] conPimienta = null;
        char[] entrada = null;
        PBEKeySpec spec = null;
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(pimienta, "HmacSHA256"));
            conPimienta = hmac.doFinal(claveLogin);
            entrada = Base64.getEncoder().encodeToString(conPimienta).toCharArray();

            spec = new PBEKeySpec(entrada, salt, p.iteraciones(), TAM_HASH * 8);
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("No se ha podido calcular el hash de la clave de login", e);
        } finally {
            if (conPimienta != null) {
                Arrays.fill(conPimienta, (byte) 0);
            }
            if (entrada != null) {
                Arrays.fill(entrada, '\0');
            }
            if (spec != null) {
                spec.clearPassword();
            }
        }
    }

    // Repite el cálculo con el salt y los parámetros guardados y compara con MessageDigest.isEqual,
    // que tarda lo mismo acierte o falle (no da pistas por el tiempo de respuesta)
    public boolean verificar(byte[] claveLogin, byte[] salt, Parametros p, byte[] hashGuardado) {
        byte[] calculado = calcular(claveLogin, salt, p);
        try {
            return MessageDigest.isEqual(calculado, hashGuardado);
        } finally {
            Arrays.fill(calculado, (byte) 0);
        }
    }

    // Para usuarios que no existen se hace el mismo trabajo, así la respuesta tarda lo mismo y no revela
    // qué nombres de usuario están registrados
    public void verificarFalso(byte[] claveLogin) {
        Arrays.fill(calcular(claveLogin, saltFalso, RECOMENDADOS), (byte) 0);
    }
}
