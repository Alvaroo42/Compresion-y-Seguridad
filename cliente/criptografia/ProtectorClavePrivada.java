package cliente.criptografia;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Protege la clave privada RSA con la clave de datos (mitad izquierda del SHA3 de la contraseña).
 * Formato: IV (12 bytes) ‖ C ‖ etiqueta (16 bytes), con AES-128-GCM.
 * Se usa GCM y no CTR porque la privada protegida se guarda en un servidor ajeno: la etiqueta de GCM
 * detecta si alguien la ha modificado. Los archivos siguen con CTR (CifradorAES).
 */
public class ProtectorClavePrivada {

    private static final String METODO = "AES/GCM/NoPadding";
    private static final int TAM_IV = 12;
    private static final int TAM_ETIQUETA_BITS = 128;
    private static final SecureRandom RANDOM = new SecureRandom();

    // Cifra la clave privada (PKCS#8) con la clave de datos
    public static byte[] proteger(PrivateKey clavePrivada, byte[] claveDatos) throws GeneralSecurityException {
        byte[] iv = new byte[TAM_IV];
        RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(METODO);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(claveDatos, "AES"), new GCMParameterSpec(TAM_ETIQUETA_BITS, iv));
        byte[] pkcs8 = clavePrivada.getEncoded();
        byte[] cifrado = cipher.doFinal(pkcs8);
        Arrays.fill(pkcs8, (byte) 0);

        return ByteBuffer.allocate(TAM_IV + cifrado.length).put(iv).put(cifrado).array();
    }

    // Recupera la clave privada con la clave de datos. Si la clave no es la correcta o los datos se han
    // modificado, GCM no valida la etiqueta y se lanza ContrasenaIncorrectaException.
    public static PrivateKey recuperar(byte[] datosProtegidos, byte[] claveDatos) throws GeneralSecurityException {
        if (datosProtegidos == null || datosProtegidos.length <= TAM_IV + TAM_ETIQUETA_BITS / 8) {
            throw new ContrasenaIncorrectaException();
        }
        try {
            Cipher cipher = Cipher.getInstance(METODO);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(claveDatos, "AES"),
                    new GCMParameterSpec(TAM_ETIQUETA_BITS, datosProtegidos, 0, TAM_IV));
            byte[] pkcs8 = cipher.doFinal(datosProtegidos, TAM_IV, datosProtegidos.length - TAM_IV);
            try {
                return CifradoRSA.cargarClavePrivada(pkcs8);
            } finally {
                Arrays.fill(pkcs8, (byte) 0);
            }
        } catch (GeneralSecurityException e) {
            throw new ContrasenaIncorrectaException();
        }
    }

    // Excepción específica para que la interfaz pueda mostrar un mensaje claro.
    public static class ContrasenaIncorrectaException extends GeneralSecurityException {
        private static final long serialVersionUID = 1L;

        public ContrasenaIncorrectaException() {
            super("Contraseña incorrecta (o clave privada dañada)");
        }
    }
}
