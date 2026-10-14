package cliente.criptografia;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Cifrado asimétrico RSA-2048 con relleno OAEP (SHA-256, MGF1-SHA-256).
 *
 * Se usa para proteger las claves AES:  K* = E_RSA-OAEP(PU, K)
 */
public class CifradoRSA {

    public static final int TAM_CLAVE_BITS = 2048;

    // Se fijan explícitamente los parámetros de OAEP para no depender del proveedor
    private static final String TRANSFORMACION = "RSA/ECB/OAEPPadding";
    private static final OAEPParameterSpec PARAMETROS_OAEP = new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    // ------------------------------------------------------------------
    // Generación del par de claves
    // ------------------------------------------------------------------

    /** Genera el par de claves RSA (PU, PR). */
    public static KeyPair generarParClaves() throws GeneralSecurityException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(TAM_CLAVE_BITS, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    // ------------------------------------------------------------------
    // Cifrado / descifrado de claves AES
    // ------------------------------------------------------------------

    /** K* = E_RSA(PU, K) */
    public static byte[] cifrarClaveAES(byte[] claveAES, PublicKey clavePublica) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(TRANSFORMACION);
        cipher.init(Cipher.ENCRYPT_MODE, clavePublica, PARAMETROS_OAEP);
        return cipher.doFinal(claveAES);
    }

    /** K = D_RSA(PR, K*) */
    public static byte[] descifrarClaveAES(byte[] claveAESCifrada, PrivateKey clavePrivada) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(TRANSFORMACION);
        cipher.init(Cipher.DECRYPT_MODE, clavePrivada, PARAMETROS_OAEP);
        return cipher.doFinal(claveAESCifrada);
    }

    // ------------------------------------------------------------------
    // Reconstrucción de claves a partir de bytes guardados en disco
    //   - Pública:  getEncoded() -> formato X.509 (SubjectPublicKeyInfo)
    //   - Privada:  getEncoded() -> formato PKCS#8
    // ------------------------------------------------------------------

    public static PublicKey cargarClavePublica(byte[] bytesX509) throws GeneralSecurityException {
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytesX509));
    }

    public static PrivateKey cargarClavePrivada(byte[] bytesPKCS8) throws GeneralSecurityException {
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(bytesPKCS8));
    }
}
