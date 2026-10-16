package cliente.almacenamiento;

import cliente.codificacion.Codificador;
import cliente.codificacion.CodificadorBase64;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Stream;

/**
 * Gestiona dónde se guardan las cosas en disco.
 *
 * datos/
 *   claves/<usuario>_publica.key   -> PU en claro (X.509) codificada en Base64
 *   claves/<usuario>_privada.cif   -> PR protegida (ver ProtectorClavePrivada) codificada en Base64
 *   cifrados/<id>.cif              -> archivos multimedia cifrados (IV || C) codificados en Base64
 *   cifrados/<id>.meta             -> metadatos: usuario, nombreOriginal, K* en Base64
 */
public class GestorFicheros {

    private static Path directorioDatos = Paths.get("datos");
    
    // Inyectamos la dependencia de codificación.
    // Esto es clave para el desacoplamiento: si en la Fase 2 quieres cambiar
    // a otra codificación, o eliminarla localmente para que la haga el servidor, 
    // solo cambias esta línea (por ejemplo a un 'CodificadorNulo').
    private static final Codificador codificador = new CodificadorBase64();

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
    // Flujos envueltos (Streams) para Archivos Grandes
    // ------------------------------------------------------------------
    
    /**
     * Devuelve un flujo de salida para escribir un archivo cifrado.
     * El flujo ya viene envuelto, por lo que todo lo que se escriba en él
     * se codificará automáticamente (ej. en Base64) antes de tocar el disco.
     */
    public static OutputStream obtenerFlujoSalidaCifrado(String idArchivo) throws IOException {
        Path ruta = rutaArchivoCifrado(idArchivo);
        OutputStream outReal = Files.newOutputStream(ruta);
        return codificador.envolverSalida(outReal);
    }
    
    /**
     * Devuelve un flujo de entrada para leer un archivo cifrado.
     * El flujo ya viene envuelto, por lo que al leer, los datos se 
     * decodificarán automáticamente recuperando los bytes crudos (cifrados).
     */
    public static InputStream obtenerFlujoEntradaCifrado(String idArchivo) throws IOException {
        Path ruta = rutaArchivoCifrado(idArchivo);
        InputStream inReal = Files.newInputStream(ruta);
        return codificador.envolverEntrada(inReal);
    }

    // ------------------------------------------------------------------
    // Metadatos de Archivos (Sustituye a AlmacenClaves y EntradaClave)
    // ------------------------------------------------------------------

    public record MetadatosArchivo(String usuario, String nombreOriginal, byte[] claveCifradaRSA) {}

    public static void guardarMetadatosArchivo(String idArchivo, String usuario, String nombreOriginal, byte[] claveCifradaRSA) throws IOException {
        Path rutaMeta = directorioCifrados().resolve(idArchivo + ".meta");
        // Usamos la interfaz del codificador en lugar de Base64 directo
        String meta = usuario + "\n" + nombreOriginal + "\n" + codificador.codificarAString(claveCifradaRSA);
        Files.writeString(rutaMeta, meta);
    }

    public static MetadatosArchivo leerMetadatosArchivo(String idArchivo) throws IOException {
        Path rutaMeta = directorioCifrados().resolve(idArchivo + ".meta");
        if (!Files.exists(rutaMeta)) return null;
        List<String> lineas = Files.readAllLines(rutaMeta);
        if (lineas.size() < 3) return null;
        // Usamos la interfaz del codificador en lugar de Base64 directo
        return new MetadatosArchivo(lineas.get(0), lineas.get(1), codificador.decodificarDeString(lineas.get(2)));
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
        // Codificamos los bytes de las claves antes de guardarlos a disco
        Files.write(rutaPublica(nombreUsuario), codificador.codificarABytes(clavePublica));
        Files.write(rutaPrivada(nombreUsuario), codificador.codificarABytes(clavePrivadaCifrada));
    }

    public static byte[] leerClavePublica(String nombreUsuario) throws IOException {
        // Leemos del disco y decodificamos para recuperar los bytes originales
        byte[] leido = Files.readAllBytes(rutaPublica(nombreUsuario));
        return codificador.decodificarDeBytes(leido);
    }

    public static byte[] leerClavePrivadaCifrada(String nombreUsuario) throws IOException {
        // Leemos del disco y decodificamos para recuperar los bytes originales
        byte[] leido = Files.readAllBytes(rutaPrivada(nombreUsuario));
        return codificador.decodificarDeBytes(leido);
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