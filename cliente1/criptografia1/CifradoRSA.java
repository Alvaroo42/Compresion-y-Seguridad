package cliente.criptografia;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;

public class CifradoRSA {

    // Genera el par de claves RSA (Pública y Privada) para el usuario
    public static KeyPair generarParClaves() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048); // 2048 bits es el estándar actual seguro para RSA
        return keyGen.generateKeyPair();
    }

    // Cifra la clave AES utilizando la clave pública RSA del usuario
    public static byte[] cifrarClaveAES(byte[] claveAES, PublicKey clavePublica) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, clavePublica);
        return cipher.doFinal(claveAES);
    }

    // Método auxiliar para comprobar que podemos descifrarla después con la privada
    public static byte[] descifrarClaveAES(byte[] claveAESCifrada, PrivateKey clavePrivada) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, clavePrivada);
        return cipher.doFinal(claveAESCifrada);
    }
}