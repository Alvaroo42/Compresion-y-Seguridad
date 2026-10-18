package cliente.criptografia;

import cliente.seguridad.DerivadorClaveContrasena;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.Arrays;

public class ProtectorClavePrivada {

    private static final int TAM_SALT = DerivadorClaveContrasena.TAM_SALT;

    // Cifra la clave privada con una clave AES derivada de la contraseña.
    public static byte[] proteger(PrivateKey clavePrivada, char[] contrasena) throws GeneralSecurityException {
        byte[] salt = DerivadorClaveContrasena.generarSalt();
        byte[] kAES = DerivadorClaveContrasena.claveAES(contrasena, salt);
        byte[] ivMasCifrado = CifradorAES.cifrar(clavePrivada.getEncoded(), kAES);   // IV || C

        byte[] resultado = ByteBuffer.allocate(TAM_SALT + ivMasCifrado.length).put(salt).put(ivMasCifrado).array();
        return resultado; 
    }

    // Recupera la clave privada con la contraseña.
    public static PrivateKey recuperar(byte[] datosProtegidos, char[] contrasena) throws GeneralSecurityException {
        byte[] salt = Arrays.copyOfRange(datosProtegidos, 0, TAM_SALT);
        byte[] ivMasCifrado = Arrays.copyOfRange(datosProtegidos, TAM_SALT, datosProtegidos.length);

        try {
            byte[] kAES = DerivadorClaveContrasena.claveAES(contrasena, salt);
            byte[] pkcs8 = CifradorAES.descifrar(ivMasCifrado, kAES);
            return CifradoRSA.cargarClavePrivada(pkcs8);
        } catch (GeneralSecurityException e) {
            throw new ContrasenaIncorrectaException();
        }
    }

    // Excepción específica para que la interfaz pueda mostrar un mensaje claro.
    public static class ContrasenaIncorrectaException extends GeneralSecurityException {
        public ContrasenaIncorrectaException() {
            super("Contraseña incorrecta (o fichero de clave privada dañado)");
        }
    }
}