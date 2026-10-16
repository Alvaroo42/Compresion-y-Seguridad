package cliente.almacenamiento;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;

/**
 * Gestiona dónde se guardan las cosas en disco.
 *
 * datos/
 *   claves/<usuario>_publica.key   -> PU en claro (X.509)
 *   claves/<usuario>_privada.cif   -> PR protegida (ver ProtectorClavePrivada)
 *   cifrados/<id>.cif              -> archivos multimedia cifrados (IV || C)
 *   cifrados/<id>.meta             -> metadatos: usuario, nombreOriginal, K* en Base64
 */
public class GestorFicheros {

    private static Path directorioDatos = Paths.get("datos");

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
    // Metadatos de Archivos (Sustituye a AlmacenClaves y EntradaClave)
    // ------------------------------------------------------------------

    public record MetadatosArchivo(String usuario, String nombreOriginal, byte[] claveCifradaRSA) {}

    public static void guardarMetadatosArchivo(String idArchivo, String usuario, String nombreOriginal, byte[] claveCifradaRSA) throws IOException {
        Path rutaMeta = directorioCifrados().resolve(idArchivo + ".meta");
        String meta = usuario + "\n" + nombreOriginal + "\n" + Base64.getEncoder().encodeToString(claveCifradaRSA);
        Files.writeString(rutaMeta, meta);
    }

    public static MetadatosArchivo leerMetadatosArchivo(String idArchivo) throws IOException {
        Path rutaMeta = directorioCifrados().resolve(idArchivo + ".meta");
        if (!Files.exists(rutaMeta)) return null;
        List<String> lineas = Files.readAllLines(rutaMeta);
        if (lineas.size() < 3) return null;
        return new MetadatosArchivo(lineas.get(0), lineas.get(1), Base64.getDecoder().decode(lineas.get(2)));
    }

    public static List<String> listarIdsArchivos() throws IOException {
        try (Stream<Path> stream = Files.list(directorioCifrados())) {
            return stream.filter(p -> p.toString().endsWith(".meta"))
                         .map(p -> p.getFileName().toString().replace(".meta", ""))
                         .toList();
        }
    }

    // ------------------------------------------------------------------
    // Claves RSA del usuario
    // ------------------------------------------------------------------

    public static void guardarClavesUsuario(String nombreUsuario, byte[] clavePublica, byte[] clavePrivadaCifrada)
            throws IOException {
        Files.write(rutaPublica(nombreUsuario), clavePublica);
        Files.write(rutaPrivada(nombreUsuario), clavePrivadaCifrada);
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