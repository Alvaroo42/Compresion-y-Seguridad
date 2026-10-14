package cliente.almacenamiento;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Gestiona dónde se guardan las cosas en disco.
 *
 * datos/
 *   claves/<usuario>_publica.key   -> PU en claro (X.509)
 *   claves/<usuario>_privada.cif   -> PR protegida (ver ProtectorClavePrivada)
 *   cifrados/<id>.cif              -> archivos multimedia cifrados (IV || C)
 *   almacen_claves.txt             -> claves AES cifradas con RSA
 */
public class GestorFicheros {

    private static Path directorioDatos = Paths.get("datos");

    /** Permite cambiar la carpeta base (útil para pruebas o para elegirla desde la interfaz). */
    public static void setDirectorioDatos(Path dir) {
        directorioDatos = dir;
    }

    public static Path getDirectorioDatos() {
        return directorioDatos;
    }

    public static Path directorioClaves() throws IOException {
        return Files.createDirectories(directorioDatos.resolve("claves"));
    }

    public static Path directorioCifrados() throws IOException {
        return Files.createDirectories(directorioDatos.resolve("cifrados"));
    }

    public static Path rutaArchivoCifrado(String idArchivo) throws IOException {
        return directorioCifrados().resolve(idArchivo + ".cif");
    }

    // ------------------------------------------------------------------
    // Claves RSA del usuario
    // ------------------------------------------------------------------

    public static void guardarClavesUsuario(String nombreUsuario, byte[] clavePublica, byte[] clavePrivadaCifrada)
            throws IOException {
        Files.write(rutaPublica(nombreUsuario), clavePublica);          // PU en claro
        Files.write(rutaPrivada(nombreUsuario), clavePrivadaCifrada);   // PR cifrada
    }

    public static byte[] leerClavePublica(String nombreUsuario) throws IOException {
        return Files.readAllBytes(rutaPublica(nombreUsuario));
    }

    public static byte[] leerClavePrivadaCifrada(String nombreUsuario) throws IOException {
        return Files.readAllBytes(rutaPrivada(nombreUsuario));
    }

    public static boolean existeUsuario(String nombreUsuario) throws IOException {
        return Files.exists(rutaPublica(nombreUsuario)) && Files.exists(rutaPrivada(nombreUsuario));
    }

    private static Path rutaPublica(String nombreUsuario) throws IOException {
        return directorioClaves().resolve(nombreUsuario + "_publica.key");
    }

    private static Path rutaPrivada(String nombreUsuario) throws IOException {
        return directorioClaves().resolve(nombreUsuario + "_privada.cif");
    }
}
