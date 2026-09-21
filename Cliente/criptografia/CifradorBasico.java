package Cliente.criptografia;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class CifradorBasico {

    public static byte[] cifrar(byte[] datosEnClaro, byte[] clave16Bytes) throws Exception {
        // Se define la especificación de la clave indicando el algoritmo
        SecretKeySpec secretKey = new SecretKeySpec(clave16Bytes, "AES");

        // Se obtiene la instancia del cifrador y se inicializa en modo cifrado
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        // Se procesan los datos y se devuelve el array de bytes cifrado
        return cipher.doFinal(datosEnClaro);
    }
}