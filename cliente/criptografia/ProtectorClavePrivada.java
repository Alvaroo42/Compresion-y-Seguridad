package cliente.criptografia;

import cliente.seguridad.DerivadorClaveContrasena;
import cliente.seguridad.DerivadorClaveContrasena.ClavesDerivadas;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.Arrays;

/**
 * Protege la clave privada RSA cifrándola con AES-128.
 *
 * La clave AES sale de la contraseña (ver cliente.seguridad.DerivadorClaveContrasena):
 *
 *   K_AES = SHA3-256(salt || contraseña)[0..127]
 *   PR*   = salt || IV || E_AES-CTR(K_AES, IV, PR)
 *
 * Formato del fichero <usuario>_privada.cif:
 *   [ salt: 16 bytes ][ IV: 16 bytes ][ PR cifrada (PKCS#8): resto ]
 */
public class ProtectorClavePrivada {

    /** Bytes que van antes de la clave privada cifrada (salt + IV). */
    public static final int TAM_CABECERA = DerivadorClaveContrasena.TAM_SALT + CifradorAES.TAM_IV;

    /** Cifra la clave privada con la clave derivada de la contraseña. Genera un salt nuevo. */
    public static byte[] proteger(PrivateKey clavePrivada, char[] contrasena) throws GeneralSecurityException {
        byte[] salt = DerivadorClaveContrasena.generarSalt();
        byte[] pkcs8 = clavePrivada.getEncoded();
        byte[] kAES = null;

        try (ClavesDerivadas claves = DerivadorClaveContrasena.derivar(contrasena, salt)) {
            kAES = claves.getClaveAES();
            byte[] ivMasCifrado = CifradorAES.cifrar(pkcs8, kAES);   // IV || C

            return ByteBuffer.allocate(salt.length + ivMasCifrado.length)
                    .put(salt)
                    .put(ivMasCifrado)
                    .array();
        } finally {
            Arrays.fill(pkcs8, (byte) 0);
            if (kAES != null) Arrays.fill(kAES, (byte) 0);
        }
    }

    /**
     * Recupera la clave privada con la contraseña.
     * Con una contraseña incorrecta sale otra K_AES, el descifrado produce bytes aleatorios
     * que no forman una clave PKCS#8 válida y se lanza ContrasenaIncorrectaException.
     */
    public static PrivateKey recuperar(byte[] datosProtegidos, char[] contrasena) throws GeneralSecurityException {
        if (datosProtegidos == null || datosProtegidos.length <= TAM_CABECERA) {
            throw new GeneralSecurityException("Fichero de clave privada corrupto");
        }
        byte[] salt = Arrays.copyOfRange(datosProtegidos, 0, DerivadorClaveContrasena.TAM_SALT);
        byte[] ivMasCifrado = Arrays.copyOfRange(datosProtegidos, DerivadorClaveContrasena.TAM_SALT,
                datosProtegidos.length);

        byte[] kAES = null;
        byte[] pkcs8 = null;
        try (ClavesDerivadas claves = DerivadorClaveContrasena.derivar(contrasena, salt)) {
            kAES = claves.getClaveAES();
            pkcs8 = CifradorAES.descifrar(ivMasCifrado, kAES);
            return CifradoRSA.cargarClavePrivada(pkcs8);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new ContrasenaIncorrectaException();
        } finally {
            if (kAES != null) Arrays.fill(kAES, (byte) 0);
            if (pkcs8 != null) Arrays.fill(pkcs8, (byte) 0);
        }
    }

    /**
     * Devuelve el token de servidor del usuario (segunda mitad del hash) usando el salt
     * guardado en su fichero de clave privada. Se usará en la Fase 2 para el login.
     */
    public static byte[] obtenerTokenServidor(byte[] datosProtegidos, char[] contrasena) throws GeneralSecurityException {
        if (datosProtegidos == null || datosProtegidos.length <= TAM_CABECERA) {
            throw new GeneralSecurityException("Fichero de clave privada corrupto");
        }
        byte[] salt = Arrays.copyOfRange(datosProtegidos, 0, DerivadorClaveContrasena.TAM_SALT);
        try (ClavesDerivadas claves = DerivadorClaveContrasena.derivar(contrasena, salt)) {
            return claves.getTokenServidor();
        }
    }

    /** Excepción específica para que la interfaz pueda mostrar un mensaje claro. */
    public static class ContrasenaIncorrectaException extends GeneralSecurityException {
        private static final long serialVersionUID = 1L;

        public ContrasenaIncorrectaException() {
            super("Contraseña incorrecta (o fichero de clave privada dañado)");
        }
    }
}
