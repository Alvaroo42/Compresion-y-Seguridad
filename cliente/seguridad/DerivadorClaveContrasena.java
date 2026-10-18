package cliente.seguridad;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

public class DerivadorClaveContrasena {

    public static final int TAM_SALT = 16;

    // Genera un salt aleatorio nuevo
    public static byte[] generarSalt() {
        byte[] salt = new byte[TAM_SALT];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    // Aplica un hash
    public static byte[] hash(char[] contrasena, byte[] salt) throws GeneralSecurityException {
        MessageDigest sha3 = MessageDigest.getInstance("SHA3-256");
        sha3.update(salt);
        sha3.update(new String(contrasena).getBytes(StandardCharsets.UTF_8));
        return sha3.digest();
    }

    // Devuelve los 128 bytes de AES, como el SHA-3 son 256 lo partimos
    public static byte[] claveAES(char[] contrasena, byte[] salt) throws GeneralSecurityException {
        return Arrays.copyOfRange(hash(contrasena, salt), 0, 16);
    }
}