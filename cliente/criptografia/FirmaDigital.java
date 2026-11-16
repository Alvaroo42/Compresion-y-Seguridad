package cliente.criptografia;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

/**
 * Mejora: firma digital e integridad de los archivos. Quien sube un archivo lo firma con su clave privada:
 *   σ = S_{k_emisor}^{SHA3-256withRSA}( "CyS-v2|firma|" ‖ K* ‖ nombre cifrado ‖ .cif )
 * y quien lo descarga lo comprueba con la clave pública del emisor antes de descifrar. Si el servidor (o
 * alguien que haya entrado en él) cambia un solo byte del archivo, de su nombre o de su clave cifrada, la
 * firma ya no coincide. AES-CTR por sí solo no detecta cambios; la firma sí, y además demuestra quién lo envió.
 */
public class FirmaDigital {

    public static final String ALGORITMO = "SHA3-256withRSA";
    private static final byte[] ETIQUETA = "CyS-v2|firma|".getBytes(StandardCharsets.UTF_8);

    public static byte[] firmar(PrivateKey clavePrivada, byte[] claveAESCifrada, String nombreCifrado, Path cif)
            throws GeneralSecurityException, IOException {
        Signature firma = Signature.getInstance(ALGORITMO);
        firma.initSign(clavePrivada);
        alimentar(firma, claveAESCifrada, nombreCifrado, cif);
        return firma.sign();
    }

    public static boolean verificar(PublicKey clavePublica, byte[] valorFirma, byte[] claveAESCifrada, String nombreCifrado, Path cif)
            throws GeneralSecurityException, IOException {
        if (valorFirma == null) {
            return false;
        }
        Signature firma = Signature.getInstance(ALGORITMO);
        firma.initVerify(clavePublica);
        alimentar(firma, claveAESCifrada, nombreCifrado, cif);
        try {
            return firma.verify(valorFirma);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    // Cada campo va precedido de su longitud para que no se puedan mover bytes de un campo a otro
    private static void alimentar(Signature firma, byte[] claveAESCifrada, String nombreCifrado, Path cif)
            throws GeneralSecurityException, IOException {
        byte[] nombre = nombreCifrado.getBytes(StandardCharsets.US_ASCII);
        firma.update(ETIQUETA);
        firma.update(ByteBuffer.allocate(4).putInt(claveAESCifrada.length).array());
        firma.update(claveAESCifrada);
        firma.update(ByteBuffer.allocate(4).putInt(nombre.length).array());
        firma.update(nombre);
        try (InputStream in = Files.newInputStream(cif)) {
            byte[] buffer = new byte[64 * 1024];
            int leidos;
            while ((leidos = in.read(buffer)) != -1) {
                firma.update(buffer, 0, leidos);
            }
        }
    }

    // Excepción para que la interfaz pueda avisar con un mensaje claro
    public static class FirmaNoValidaException extends GeneralSecurityException {
        private static final long serialVersionUID = 1L;

        public FirmaNoValidaException(String mensaje) {
            super(mensaje);
        }
    }
}
