package cliente.criptografia;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import javax.crypto.spec.IvParameterSpec;

public class CifradorAES {

    public static byte[] cifrar(byte[] datosEnClaro, byte[] clave16Bytes) throws Exception {
        // Se define la especificación de la clave indicando el algoritmo
        SecretKeySpec secretKey = new SecretKeySpec(clave16Bytes, "AES");

        // Se obtiene la instancia del cifrador y se inicializa en modo cifrado
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");

        // Generación del IV/Nonce (16 bytes aleatorios)
        byte[] ivBytes = new byte[16];
        new SecureRandom().nextBytes(ivBytes); // Generación criptográficamente segura
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

        // Inicializamos el cifrador pasándole la clave y el IV
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        // Ejecutamos el cifrado
        byte[] criptogramaPuro = cipher.doFinal(datosEnClaro);

        // Lo más habitual es pegarlo al principio del archivo cifrado. El IV se necesita para descifrar.
        byte[] criptogramaFinalConIV = new byte[ivBytes.length + criptogramaPuro.length];

        // Copiamos el IV en los primeros 16 bytes
        System.arraycopy(ivBytes, 0, criptogramaFinalConIV, 0, ivBytes.length);
        // Copiamos el archivo cifrado a continuación
        System.arraycopy(criptogramaPuro, 0, criptogramaFinalConIV, ivBytes.length, criptogramaPuro.length);
        
        return criptogramaFinalConIV;
    }

    public static byte[] descifrar(byte[] datosCifradosConIV, byte[] clave16Bytes) throws Exception {
        
        // Extraer el IV (los primeros 16 bytes)
        byte[] ivBytes = new byte[16];
        System.arraycopy(datosCifradosConIV, 0, ivBytes, 0, 16);
        
        // Extraer el criptograma puro (el resto del archivo)
        byte[] criptogramaPuro = new byte[datosCifradosConIV.length - 16];
        System.arraycopy(datosCifradosConIV, 16, criptogramaPuro, 0, criptogramaPuro.length);
        
        // Reconstruir la Clave y el IV
        SecretKeySpec secretKey = new SecretKeySpec(clave16Bytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        
        // Inicializar en Modo Descifrado respetando la misma configuración del profesor
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        
        // Recuperar el archivo multimedia original
        return cipher.doFinal(criptogramaPuro);
    }
}