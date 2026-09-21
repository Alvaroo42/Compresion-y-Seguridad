package Cliente.criptografia;

import java.security.MessageDigest;
import java.util.Arrays;

public class HashUtils {

    // Transforma una contraseña de texto en una clave AES de 128 bits usando SHA-3
    public static byte[] derivarClaveDesdePassword(String password) throws Exception {
        
        // 1. Aplicamos la función hash SHA-3 a 256 bits exigida por la práctica
        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        byte[] hashCompleto = digest.digest(password.getBytes("UTF-8"));
        
        // 2. DETALLE DE MATRÍCULA: SHA3-256 devuelve 32 bytes (256 bits), 
        // pero AES128 exige estrictamente una clave de 16 bytes (128 bits).
        // Por tanto, truncamos el hash para quedarnos con los primeros 16 bytes.
        return Arrays.copyOf(hashCompleto, 16);
    }
}