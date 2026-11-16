package pruebas;

import servidor.seguridad.HashClaveLogin;
import servidor.seguridad.HashClaveLogin.Parametros;

import java.util.Arrays;
import java.util.HexFormat;

/** Paso 3 de la guía: HashClaveLogin verifica la clave correcta y rechaza una incorrecta. */
public class PruebaPaso3HashLogin {

    public static void main(String[] args) {
        Comprobaciones c = new Comprobaciones();
        HexFormat hex = HexFormat.of();
        byte[] pimienta = HashClaveLogin.nuevaPimienta();
        HashClaveLogin hash = new HashClaveLogin(pimienta);
        Parametros p = HashClaveLogin.RECOMENDADOS;

        byte[] claveLogin = hex.parseHex("2659d65fecb81a0c094897901461845c");
        byte[] salt = HashClaveLogin.nuevoSalt();
        long t0 = System.nanoTime();
        byte[] guardado = hash.calcular(claveLogin, salt, p);
        long ms = (System.nanoTime() - t0) / 1_000_000;
        System.out.println("     Argon2id(" + p.memoriaKiB() + " KiB, " + p.iteraciones() + " iteraciones, paralelismo " + p.paralelismo() + ") = "
                + hex.formatHex(guardado) + "  (" + ms + " ms)");

        c.comprobar("el hash mide 32 bytes", guardado.length == 32);
        c.comprobar("la clave de login correcta se acepta", hash.verificar(claveLogin, salt, p, guardado));
        byte[] incorrecta = claveLogin.clone();
        incorrecta[0] ^= 1;
        c.comprobar("una clave de login con un bit distinto se rechaza", !hash.verificar(incorrecta, salt, p, guardado));
        c.comprobar("la misma clave con otro salt da otro hash", !Arrays.equals(guardado, hash.calcular(claveLogin, HashClaveLogin.nuevoSalt(), p)));
        HashClaveLogin otraPimienta = new HashClaveLogin(HashClaveLogin.nuevaPimienta());
        c.comprobar("sin la pimienta del servidor el hash robado no sirve", !otraPimienta.verificar(claveLogin, salt, p, guardado));
        c.comprobar("con otros parámetros sale otro hash (por eso se guardan en el perfil)",
                !Arrays.equals(guardado, hash.calcular(claveLogin, salt, new Parametros(p.memoriaKiB(), 3, 1))));
        c.comprobar("Argon2id es lento a propósito (> 10 ms por intento): " + ms + " ms", ms > 10);
        c.comprobar("pimienta de tamaño incorrecto -> error", Comprobaciones.excepcionDe(() -> new HashClaveLogin(new byte[5])) instanceof IllegalArgumentException);
        c.terminar("Paso 3");
    }
}
