package cliente.seguridad;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * De una sola contraseña salen dos claves independientes:
 *   H = SHA3-256(salt ‖ contraseña)   (32 bytes)
 *   clave de datos = H[0..15]  → clave AES-128 que cifra la clave privada RSA. Nunca sale del cliente.
 *   clave de login = H[16..31] → se envía al servidor en /REGISTRO y /LOGIN.
 * Conocer la clave de login no permite calcular la de datos: son bytes distintos del mismo hash.
 */
public class DerivadorClaveContrasena {

    public static final int TAM_SALT = 16;
    public static final int TAM_CLAVE = 16;
    private static final String PREFIJO_SALT = "CyS-v2|";

    // Las dos mitades del hash de la contraseña
    public record ClavesDerivadas(byte[] datos, byte[] login) {

        // Borra las dos claves de memoria
        public void borrar() {
            Arrays.fill(datos, (byte) 0);
            Arrays.fill(login, (byte) 0);
        }
    }

    // Salt determinista: salt = SHA3-256("CyS-v2|" + usuario)[0..15]. El cliente lo necesita antes de hablar con
    // el servidor, así que no se guarda en ningún sitio: se recalcula a partir del nombre de usuario.
    public static byte[] saltDe(String usuario) throws GeneralSecurityException {
        MessageDigest sha3 = MessageDigest.getInstance("SHA3-256");
        byte[] h = sha3.digest((PREFIJO_SALT + usuario).getBytes(StandardCharsets.UTF_8));
        return Arrays.copyOf(h, TAM_SALT);
    }

    // H = SHA3-256(salt ‖ contraseña) y se parte por la mitad
    public static ClavesDerivadas derivar(char[] contrasena, byte[] salt) throws GeneralSecurityException {
        MessageDigest sha3 = MessageDigest.getInstance("SHA3-256");
        sha3.update(salt);

        // La contraseña se pasa a UTF-8 sin crear un String, para poder borrarla de memoria después
        ByteBuffer utf8 = StandardCharsets.UTF_8.encode(CharBuffer.wrap(contrasena));
        byte[] bytesContrasena = new byte[utf8.remaining()];
        utf8.get(bytesContrasena);
        sha3.update(bytesContrasena);

        byte[] h = sha3.digest();
        ClavesDerivadas claves = new ClavesDerivadas(Arrays.copyOfRange(h, 0, TAM_CLAVE), Arrays.copyOfRange(h, TAM_CLAVE, 2 * TAM_CLAVE));

        Arrays.fill(bytesContrasena, (byte) 0);
        if (utf8.hasArray()) {
            Arrays.fill(utf8.array(), (byte) 0);
        }
        Arrays.fill(h, (byte) 0);
        return claves;
    }
}
