package pruebas;

import cliente.criptografia.CifradoRSA;
import cliente.criptografia.ProtectorClavePrivada;
import cliente.criptografia.ProtectorClavePrivada.ContrasenaIncorrectaException;
import cliente.seguridad.DerivadorClaveContrasena;
import cliente.seguridad.DerivadorClaveContrasena.ClavesDerivadas;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.HexFormat;

/** Paso 1 de la guía: la misma contraseña da siempre las mismas dos claves y son distintas entre sí. */
public class PruebaPaso1Claves {

    public static void main(String[] args) throws Exception {
        Comprobaciones c = new Comprobaciones();
        HexFormat hex = HexFormat.of();

        Comprobaciones.apartado("Derivación: H = SHA3-256(salt ‖ contraseña), datos = H[0..15], login = H[16..31]");
        byte[] saltAna = DerivadorClaveContrasena.saltDe("ana");
        ClavesDerivadas a1 = DerivadorClaveContrasena.derivar("contraseña-ana".toCharArray(), saltAna);
        ClavesDerivadas a2 = DerivadorClaveContrasena.derivar("contraseña-ana".toCharArray(), DerivadorClaveContrasena.saltDe("ana"));
        System.out.println("     salt(ana)       = " + hex.formatHex(saltAna));
        System.out.println("     clave de datos  = " + hex.formatHex(a1.datos()));
        System.out.println("     clave de login  = " + hex.formatHex(a1.login()));
        c.comprobar("el salt es determinista y mide 16 bytes", Arrays.equals(saltAna, DerivadorClaveContrasena.saltDe("ana")) && saltAna.length == 16);
        c.comprobar("misma contraseña -> misma clave de datos", Arrays.equals(a1.datos(), a2.datos()));
        c.comprobar("misma contraseña -> misma clave de login", Arrays.equals(a1.login(), a2.login()));
        c.comprobar("las dos claves miden 16 bytes (AES-128)", a1.datos().length == 16 && a1.login().length == 16);
        c.comprobar("clave de datos distinta de clave de login", !Arrays.equals(a1.datos(), a1.login()));

        ClavesDerivadas otraContrasena = DerivadorClaveContrasena.derivar("contraseña-anA".toCharArray(), saltAna);
        c.comprobar("cambiar una letra de la contraseña cambia las dos claves",
                !Arrays.equals(a1.datos(), otraContrasena.datos()) && !Arrays.equals(a1.login(), otraContrasena.login()));
        ClavesDerivadas luis = DerivadorClaveContrasena.derivar("contraseña-ana".toCharArray(), DerivadorClaveContrasena.saltDe("luis"));
        c.comprobar("misma contraseña en otro usuario (otro salt) -> claves distintas", !Arrays.equals(a1.datos(), luis.datos()));
        ClavesDerivadas conTilde = DerivadorClaveContrasena.derivar("ñandú€".toCharArray(), saltAna);
        c.comprobar("contraseñas con ñ, tildes y € funcionan (UTF-8)", conTilde.datos().length == 16);

        char[] contrasena = "se-borra".toCharArray();
        ClavesDerivadas temp = DerivadorClaveContrasena.derivar(contrasena, saltAna);
        temp.borrar();
        c.comprobar("borrar() pone las claves a cero", Arrays.equals(temp.datos(), new byte[16]) && Arrays.equals(temp.login(), new byte[16]));

        Comprobaciones.apartado("Clave privada protegida con la clave de datos (AES-128-GCM)");
        KeyPair par = CifradoRSA.generarParClaves();
        byte[] protegida = ProtectorClavePrivada.proteger(par.getPrivate(), a1.datos());
        System.out.println("     privada protegida: " + protegida.length + " bytes = IV(12) ‖ C ‖ etiqueta(16)");
        PrivateKey recuperada = ProtectorClavePrivada.recuperar(protegida, a2.datos());
        c.comprobar("con la clave de datos correcta se recupera la misma privada", Arrays.equals(recuperada.getEncoded(), par.getPrivate().getEncoded()));
        c.comprobar("dos protecciones de la misma privada dan bytes distintos (IV aleatorio)",
                !Arrays.equals(protegida, ProtectorClavePrivada.proteger(par.getPrivate(), a1.datos())));
        Throwable t = Comprobaciones.excepcionDe(() -> ProtectorClavePrivada.recuperar(protegida, otraContrasena.datos()));
        c.comprobar("con otra contraseña -> ContrasenaIncorrectaException", t instanceof ContrasenaIncorrectaException);
        t = Comprobaciones.excepcionDe(() -> ProtectorClavePrivada.recuperar(protegida, a1.login()));
        c.comprobar("la clave de login NO sirve para descifrar la privada", t instanceof ContrasenaIncorrectaException);
        byte[] manipulada = protegida.clone();
        manipulada[100] ^= 1;
        t = Comprobaciones.excepcionDe(() -> ProtectorClavePrivada.recuperar(manipulada, a1.datos()));
        c.comprobar("si se cambia un solo bit, GCM lo detecta", t instanceof ContrasenaIncorrectaException);
        t = Comprobaciones.excepcionDe(() -> ProtectorClavePrivada.recuperar(new byte[5], a1.datos()));
        c.comprobar("datos demasiado cortos -> ContrasenaIncorrectaException", t instanceof ContrasenaIncorrectaException);

        c.terminar("Paso 1");
    }
}
