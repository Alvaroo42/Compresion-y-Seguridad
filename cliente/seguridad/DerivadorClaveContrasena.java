package Cliente.seguridad;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Convierte la contraseña del usuario en claves de longitud fija mediante SHA3-256.
 *
 * Esquema:
 *
 *     H = SHA3-256( salt || UTF-8(contraseña) )            -> 256 bits
 *
 *     H = [ bits 0..127   |   bits 128..255 ]
 *           K_AES             T_servidor
 *
 *   - K_AES (128 bits): clave AES-128 que cifra la clave privada RSA. NUNCA sale del cliente.
 *   - T_servidor (128 bits): token de autenticación para el login contra el servidor (Fase 2).
 *     Conocer T_servidor no permite calcular K_AES (propiedad de un solo sentido del hash).
 *
 * El salt (16 bytes aleatorios, no secreto) se guarda junto a la clave privada cifrada.
 * Evita que dos usuarios con la misma contraseña obtengan la misma clave y anula
 * las tablas precalculadas (rainbow tables).
 *
 * Ni la contraseña, ni H, ni K_AES se almacenan nunca: se recalculan en cada inicio de sesión.
 *
 * Uso típico:
 *
 *     byte[] salt = DerivadorClaveContrasena.generarSalt();
 *     try (ClavesDerivadas c = DerivadorClaveContrasena.derivar(contrasena, salt)) {
 *         byte[] kAES = c.getClaveAES();
 *         ...
 *     }   // al salir del try, las claves se borran de memoria
 */
public final class DerivadorClaveContrasena {

    public static final String ALGORITMO_HASH = "SHA3-256";
    public static final int TAM_HASH  = 32;  // 256 bits
    public static final int TAM_SALT  = 16;  // 128 bits
    public static final int TAM_CLAVE_AES = 16;  // primera mitad del hash
    public static final int TAM_TOKEN     = 16;  // segunda mitad del hash

    private static final SecureRandom RANDOM = new SecureRandom();

    private DerivadorClaveContrasena() {
        // clase de utilidades: no se instancia
    }

    /** Genera un salt aleatorio nuevo (uno por usuario, al darse de alta). */
    public static byte[] generarSalt() {
        byte[] salt = new byte[TAM_SALT];
        RANDOM.nextBytes(salt);
        return salt;
    }

    /**
     * Calcula H = SHA3-256(salt || UTF-8(contraseña)) completo (32 bytes).
     * Normalmente se usa derivar(); este método es útil para pruebas y para la memoria.
     */
    public static byte[] hash(char[] contrasena, byte[] salt) throws GeneralSecurityException {
        comprobarEntrada(contrasena, salt);
        byte[] bytesContrasena = aUTF8(contrasena);
        try {
            MessageDigest sha3 = MessageDigest.getInstance(ALGORITMO_HASH);
            sha3.update(salt);
            sha3.update(bytesContrasena);
            return sha3.digest();
        } finally {
            Arrays.fill(bytesContrasena, (byte) 0);
        }
    }

    /** Deriva K_AES y T_servidor a partir de la contraseña y el salt del usuario. */
    public static ClavesDerivadas derivar(char[] contrasena, byte[] salt) throws GeneralSecurityException {
        byte[] h = hash(contrasena, salt);
        try {
            byte[] claveAES = Arrays.copyOfRange(h, 0, TAM_CLAVE_AES);
            byte[] token    = Arrays.copyOfRange(h, TAM_CLAVE_AES, TAM_CLAVE_AES + TAM_TOKEN);
            return new ClavesDerivadas(claveAES, token);
        } finally {
            Arrays.fill(h, (byte) 0);
        }
    }

    // ------------------------------------------------------------------
    // Resultado de la derivación
    // ------------------------------------------------------------------

    /**
     * Las dos mitades del hash. Implementa AutoCloseable para usarlo en try-with-resources
     * y que las claves se sobrescriban con ceros al terminar.
     */
    public static final class ClavesDerivadas implements AutoCloseable {

        private final byte[] claveAES;
        private final byte[] tokenServidor;

        private ClavesDerivadas(byte[] claveAES, byte[] tokenServidor) {
            this.claveAES = claveAES;
            this.tokenServidor = tokenServidor;
        }

        /** Clave AES-128 para cifrar/descifrar la clave privada (copia). */
        public byte[] getClaveAES() {
            return claveAES.clone();
        }

        /** Token para autenticarse ante el servidor en la Fase 2 (copia). */
        public byte[] getTokenServidor() {
            return tokenServidor.clone();
        }

        /** Borra las claves de memoria. */
        @Override
        public void close() {
            Arrays.fill(claveAES, (byte) 0);
            Arrays.fill(tokenServidor, (byte) 0);
        }
    }

    // ------------------------------------------------------------------
    // Auxiliares
    // ------------------------------------------------------------------

    /**
     * char[] -> bytes UTF-8 sin pasar por String (los String no se pueden borrar de memoria).
     * Siempre UTF-8: si un equipo usara windows-1252, la 'ñ' daría otros bytes y otro hash.
     */
    private static byte[] aUTF8(char[] contrasena) {
        ByteBuffer bb = StandardCharsets.UTF_8.encode(CharBuffer.wrap(contrasena));
        byte[] bytes = Arrays.copyOfRange(bb.array(), bb.position(), bb.limit());
        Arrays.fill(bb.array(), (byte) 0);
        return bytes;
    }

    private static void comprobarEntrada(char[] contrasena, byte[] salt) {
        if (contrasena == null || contrasena.length == 0) {
            throw new IllegalArgumentException("La contraseña no puede estar vacía");
        }
        if (salt == null || salt.length != TAM_SALT) {
            throw new IllegalArgumentException("El salt debe tener " + TAM_SALT + " bytes");
        }
    }
}
