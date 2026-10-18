package cliente.criptografia;

import javax.crypto.Cipher;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class CifradoRSA {

    public static final int TAM_CLAVE_BITS = 2048;
    private static final String METODO = "RSA";

    // Genera el par de claves RSA
    public static KeyPair generarParClaves() throws GeneralSecurityException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(TAM_CLAVE_BITS, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    // Cifrar clave AES con RSA
    public static byte[] cifrarClaveAES(byte[] claveAES, PublicKey clavePublica) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(METODO);
        cipher.init(Cipher.ENCRYPT_MODE, clavePublica);
        return cipher.doFinal(claveAES);
    }

    // Descifrar clave AES con RSA
    public static byte[] descifrarClaveAES(byte[] claveAESCifrada, PrivateKey clavePrivada) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(METODO);
        cipher.init(Cipher.DECRYPT_MODE, clavePrivada);
        return cipher.doFinal(claveAESCifrada);
    }

    // Reconstruir clave Publica de una cadena de bytes
    public static PublicKey cargarClavePublica(byte[] clavePublica) throws GeneralSecurityException {
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(clavePublica));
    }

    // Reconstruir clave Privada de una cadena de bytes
    public static PrivateKey cargarClavePrivada(byte[] clavePrivada) throws GeneralSecurityException {
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(clavePrivada));
    }
}
