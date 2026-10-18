package cliente.almacenamiento;

import cliente.codificacion.Codificador;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Stream;

public class GestorFicheros {

    private static Path directorioDatos = Paths.get("datos");
    private static final Codificador codificador = new Codificador();
    
    // Crea/devuelve carpeta de claves dentro de datos
    public static Path directorioClaves() throws IOException {
        return Files.createDirectories(directorioDatos.resolve("claves"));
    }

    // Crea/devuelve carpeta de cifrados dentro de datos
    public static Path directorioCifrados() throws IOException {
        return Files.createDirectories(directorioDatos.resolve("cifrados"));
    }

    // Devuelve el directorio del fichero de archivo cifrado
    public static Path rutaArchivoCifrado(String idArchivo) throws IOException {
        return directorioCifrados().resolve(idArchivo + ".cif");
    }

    // Devuelve un flujo de salida para escribir un archivo cifrado.
    public static OutputStream obtenerFlujoSalidaCifrado(String idArchivo) throws IOException {
        Path ruta = rutaArchivoCifrado(idArchivo);
        OutputStream outReal = Files.newOutputStream(ruta);
        return codificador.envolverSalida(outReal);
    }
    
    // Devuelve un flujo de entrada para leer un archivo cifrado.
    public static InputStream obtenerFlujoEntradaCifrado(String idArchivo) throws IOException {
        Path ruta = rutaArchivoCifrado(idArchivo);
        InputStream inReal = Files.newInputStream(ruta);
        return codificador.envolverEntrada(inReal);
    }

    // Agrupar metadatos
    public record MetadatosArchivo(String usuario, String nombreOriginal, byte[] claveCifradaRSA) {}

    // Escribe los metadatos en el archivo de metadatos
    public static void guardarMetadatosArchivo(String idArchivo, String usuario, String nombreOriginal, byte[] claveCifradaRSA) throws IOException {
        Path rutaMeta = directorioCifrados().resolve(idArchivo + ".meta");
        String meta = usuario + "\n" + nombreOriginal + "\n" + codificador.codificarAString(claveCifradaRSA);
        Files.writeString(rutaMeta, meta);
    }

    // Devolver metadatos de un archivo .meta
    public static MetadatosArchivo leerMetadatosArchivo(String idArchivo) throws IOException {
        Path rutaMeta = directorioCifrados().resolve(idArchivo + ".meta");
        if (!Files.exists(rutaMeta)) 
            return null;
        List<String> lineas = Files.readAllLines(rutaMeta);
        if (lineas.size() < 3) 
            return null;
        return new MetadatosArchivo(lineas.get(0), lineas.get(1), codificador.decodificarDeString(lineas.get(2)));
    }

    // Devuelve la lista de nombres de todos los archivos cifrados
    public static List<String> listarIdsArchivos() throws IOException {
        try (Stream<Path> stream = Files.list(directorioCifrados())) {
            return stream.filter(p -> p.toString().endsWith(".meta")).map(p -> p.getFileName().
                toString().replace(".meta", "")).toList();
        }
    }

    // 
    public static void guardarClavesUsuario(String nombreUsuario, byte[] clavePublica, byte[] clavePrivadaCifrada) throws IOException {
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

    // Devuelve 
    private static Path rutaPublica(String nombreUsuario) throws IOException {
        return directorioClaves().resolve(nombreUsuario + "_publica.key");
    }

    private static Path rutaPrivada(String nombreUsuario) throws IOException {
        return directorioClaves().resolve(nombreUsuario + "_privada.cif");
    }
}