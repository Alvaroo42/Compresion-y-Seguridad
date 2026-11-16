package servidor.seguridad;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * El servidor recibe la clave de login (16 bytes) y la vuelve a resumir con Argon2id, un algoritmo lento a
 * propósito: si alguien roba la carpeta de datos, no puede usar los hashes para entrar y probar contraseñas
 * le sale muy caro.
 *   hashLogin = Argon2id(claveLogin, salt, pimienta; memoria, iteraciones, paralelismo)
 * - salt: 16 bytes aleatorios por usuario, guardados en su perfil.
 * - pimienta: secreto de 32 bytes común a todo el servidor, guardado FUERA de servidor_datos.
 * - parámetros: se guardan junto al hash para poder subirlos más adelante sin romper los usuarios antiguos.
 * Implementación de Bouncy Castle (lib/bcprov.jar): el JDK no incluye Argon2.
 */
public class HashClaveLogin {

    public static final String ALGORITMO = "argon2id";
    public static final int TAM_SALT = 16;
    public static final int TAM_HASH = 32;
    public static final int TAM_PIMIENTA = 32;

    // Coste de Argon2id. Los recomendados por OWASP: 19 MiB de memoria, 2 iteraciones y paralelismo 1
    public record Parametros(int memoriaKiB, int iteraciones, int paralelismo) {
    }

    public static final Parametros RECOMENDADOS = new Parametros(19456, 2, 1);

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

    // Argon2id(claveLogin) con el salt del usuario y la pimienta del servidor como "secret" de Argon2
    public byte[] calcular(byte[] claveLogin, byte[] salt, Parametros p) {
        Argon2Parameters parametros = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withSalt(salt)
                .withSecret(pimienta)
                .withMemoryAsKB(p.memoriaKiB())
                .withIterations(p.iteraciones())
                .withParallelism(p.paralelismo())
                .build();
        Argon2BytesGenerator generador = new Argon2BytesGenerator();
        generador.init(parametros);
        byte[] hash = new byte[TAM_HASH];
        generador.generateBytes(claveLogin, hash);
        return hash;
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
