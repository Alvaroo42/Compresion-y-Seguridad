package cliente.criptografia;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

public class CifradorAES {

    public static final String METODO = "AES/CTR/NoPadding";
    public static final int TAM_CLAVE_BITS = 128;
    public static final int TAM_CLAVE_BYTES = TAM_CLAVE_BITS / 8;
    public static final int TAM_IV = 16;
    private static final int TAM_BUFFER = 64 * 1024;
    private static final SecureRandom RANDOM = new SecureRandom();


    // Genera una clave AES-128 aleatoria (una distinta para cada archivo).
    public static byte[] generarClaveAES() throws GeneralSecurityException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(TAM_CLAVE_BITS, RANDOM);
        return keyGen.generateKey().getEncoded();
    }

    // Genera un IV/nonce aleatorio de 16 bytes.
    public static byte[] generarIV() {
        byte[] iv = new byte[TAM_IV];
        RANDOM.nextBytes(iv);
        return iv;
    }

    // Cifrar con AES
    public static byte[] cifrar(byte[] datosEnClaro, byte[] clave16Bytes) throws GeneralSecurityException {
        comprobarClave(clave16Bytes);
        byte[] iv = generarIV();

        Cipher cipher = crearCipher(Cipher.ENCRYPT_MODE, clave16Bytes, iv);
        byte[] datosCifrados = cipher.doFinal(datosEnClaro);

        byte[] datosCifradosConIV = new byte[TAM_IV + datosCifrados.length];
        System.arraycopy(iv, 0, datosCifradosConIV, 0, TAM_IV);
        System.arraycopy(datosCifrados, 0, datosCifradosConIV, TAM_IV, datosCifrados.length);
        return datosCifradosConIV;
    }

    // Descifrar con AES
    public static byte[] descifrar(byte[] datosCifradosConIV, byte[] clave16Bytes) throws GeneralSecurityException {
        comprobarClave(clave16Bytes);
        if (datosCifradosConIV == null || datosCifradosConIV.length < TAM_IV) {
            throw new GeneralSecurityException("Datos cifrados demasiado cortos: falta el IV");
        }
        byte[] iv = new byte[TAM_IV];
        System.arraycopy(datosCifradosConIV, 0, iv, 0, TAM_IV);

        Cipher cipher = crearCipher(Cipher.DECRYPT_MODE, clave16Bytes, iv);
        byte[] datosEnClaro = cipher.doFinal(datosCifradosConIV, TAM_IV, datosCifradosConIV.length - TAM_IV);
        return datosEnClaro; 
    }

    // Cifrado en flujo
    public static void cifrarFlujo(InputStream in, OutputStream out, byte[] clave16Bytes) throws GeneralSecurityException, IOException {
        comprobarClave(clave16Bytes);
        byte[] iv = generarIV();
        Cipher cipher = crearCipher(Cipher.ENCRYPT_MODE, clave16Bytes, iv);

        out.write(iv);
        
        try (CipherOutputStream flujoCifrado = new CipherOutputStream(out, cipher)) {
            copiar(in, flujoCifrado);
        }
    }

    // Descifrado en flujo
    public static void descifrarFlujo(InputStream in, OutputStream out, byte[] clave16Bytes) throws GeneralSecurityException, IOException {
        comprobarClave(clave16Bytes);

        byte[] iv = in.readNBytes(TAM_IV);
        if (iv.length != TAM_IV) {
            throw new GeneralSecurityException("Flujo cifrado corrupto: no contiene IV completo");
        }
        Cipher cipher = crearCipher(Cipher.DECRYPT_MODE, clave16Bytes, iv);

        try (CipherInputStream flujoDescifrado = new CipherInputStream(in, cipher)) {
            copiar(flujoDescifrado, out);
            out.flush();
        }
    }

    // Inicializar cifrado
    private static Cipher crearCipher(int modo, byte[] clave, byte[] iv) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(METODO);
        cipher.init(modo, new SecretKeySpec(clave, "AES"), new IvParameterSpec(iv));
        return cipher;
    }

    // Comprobar existencia de Clave y tamaño
    private static void comprobarClave(byte[] clave) throws GeneralSecurityException {
        if (clave == null || clave.length != TAM_CLAVE_BYTES) {
            throw new GeneralSecurityException("La clave AES-128 debe tener exactamente 16 bytes");
        }
    }

    // Cargar el archivo en pequeños bloques
    private static void copiar(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[TAM_BUFFER];
        int leidos;
        while ((leidos = in.read(buffer)) != -1) {
            out.write(buffer, 0, leidos);
        }
    }
}
