package cliente.criptografia;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * Cifrado simétrico AES-128 en modo CTR.
 *
 * Formato de un archivo/bloque cifrado:  IV (16 bytes) || C
 * donde C = E_AES-CTR(K, IV, M)
 */
public class CifradorAES {

    public static final String TRANSFORMACION = "AES/CTR/NoPadding";
    public static final int TAM_CLAVE_BITS = 128;
    public static final int TAM_CLAVE_BYTES = TAM_CLAVE_BITS / 8;
    public static final int TAM_IV = 16;

    private static final int TAM_BUFFER = 64 * 1024; // 64 KB por lectura
    private static final SecureRandom RANDOM = new SecureRandom();

    // ------------------------------------------------------------------
    // Generación de claves e IV
    // ------------------------------------------------------------------

    /** Genera una clave AES-128 aleatoria (una distinta para cada archivo). */
    public static byte[] generarClaveAES() throws GeneralSecurityException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(TAM_CLAVE_BITS, RANDOM);
        return keyGen.generateKey().getEncoded();
    }

    /** Genera un IV/nonce aleatorio de 16 bytes. */
    public static byte[] generarIV() {
        byte[] iv = new byte[TAM_IV];
        RANDOM.nextBytes(iv);
        return iv;
    }

    // ------------------------------------------------------------------
    // Cifrado en memoria (para datos pequeños: claves, cabeceras...)
    // ------------------------------------------------------------------

    /** Devuelve IV || E_AES-CTR(K, IV, datosEnClaro). */
    public static byte[] cifrar(byte[] datosEnClaro, byte[] clave16Bytes) throws GeneralSecurityException {
        comprobarClave(clave16Bytes);
        byte[] iv = generarIV();

        Cipher cipher = crearCipher(Cipher.ENCRYPT_MODE, clave16Bytes, iv);
        byte[] criptograma = cipher.doFinal(datosEnClaro);

        byte[] resultado = new byte[TAM_IV + criptograma.length];
        System.arraycopy(iv, 0, resultado, 0, TAM_IV);
        System.arraycopy(criptograma, 0, resultado, TAM_IV, criptograma.length);
        return resultado;
    }

    /** Recibe IV || C y devuelve el texto en claro. */
    public static byte[] descifrar(byte[] datosCifradosConIV, byte[] clave16Bytes) throws GeneralSecurityException {
        comprobarClave(clave16Bytes);
        if (datosCifradosConIV == null || datosCifradosConIV.length < TAM_IV) {
            throw new GeneralSecurityException("Datos cifrados demasiado cortos: falta el IV");
        }
        byte[] iv = new byte[TAM_IV];
        System.arraycopy(datosCifradosConIV, 0, iv, 0, TAM_IV);

        Cipher cipher = crearCipher(Cipher.DECRYPT_MODE, clave16Bytes, iv);
        return cipher.doFinal(datosCifradosConIV, TAM_IV, datosCifradosConIV.length - TAM_IV);
    }

    // ------------------------------------------------------------------
    // Cifrado de archivos por flujo (streaming): válido para vídeos de GB
    // sin cargarlos enteros en memoria.
    // ------------------------------------------------------------------

    /** Cifra 'origen' y escribe IV || C en 'destino'. */
    public static void cifrarArchivo(Path origen, Path destino, byte[] clave16Bytes)
            throws GeneralSecurityException, IOException {
        comprobarClave(clave16Bytes);
        byte[] iv = generarIV();
        Cipher cipher = crearCipher(Cipher.ENCRYPT_MODE, clave16Bytes, iv);

        try (InputStream in = Files.newInputStream(origen);
             OutputStream out = new BufferedOutputStream(Files.newOutputStream(destino), TAM_BUFFER)) {
            out.write(iv); // el IV va en claro al principio: se necesita para descifrar
            CipherOutputStream cos = new CipherOutputStream(out, cipher);
            copiar(in, cos);
            cos.close();   // ejecuta doFinal() y cierra 'out'
        }
    }

    /** Lee IV || C de 'origen' y escribe el archivo original en 'destino'. */
    public static void descifrarArchivo(Path origen, Path destino, byte[] clave16Bytes)
            throws GeneralSecurityException, IOException {
        comprobarClave(clave16Bytes);

        try (InputStream in = Files.newInputStream(origen)) {
            byte[] iv = in.readNBytes(TAM_IV);
            if (iv.length != TAM_IV) {
                throw new GeneralSecurityException("Archivo cifrado corrupto: no contiene IV completo");
            }
            Cipher cipher = crearCipher(Cipher.DECRYPT_MODE, clave16Bytes, iv);

            try (CipherInputStream cis = new CipherInputStream(in, cipher);
                 OutputStream out = new BufferedOutputStream(Files.newOutputStream(destino), TAM_BUFFER)) {
                copiar(cis, out);
            }
        }
    }

    // ------------------------------------------------------------------
    // Auxiliares
    // ------------------------------------------------------------------

    private static Cipher crearCipher(int modo, byte[] clave, byte[] iv) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(TRANSFORMACION);
        cipher.init(modo, new SecretKeySpec(clave, "AES"), new IvParameterSpec(iv));
        return cipher;
    }

    private static void comprobarClave(byte[] clave) throws GeneralSecurityException {
        if (clave == null || clave.length != TAM_CLAVE_BYTES) {
            throw new GeneralSecurityException("La clave AES-128 debe tener exactamente 16 bytes");
        }
    }

    private static void copiar(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[TAM_BUFFER];
        int leidos;
        while ((leidos = in.read(buffer)) != -1) {
            out.write(buffer, 0, leidos);
        }
    }
}
