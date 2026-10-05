package cliente.encriptar;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Stream;

import cliente.almacenamiento.ProcesadorMultimedia;
import cliente.criptografia.GeneradorClaves;

public class CifrarDescifrar {

    // Carpeta general donde se guarda todo lo cifrado
    private static final String CARPETA_GENERAL = "almacenamiento_general";
    private static final String PREFIJO_CARPETA = "Archivo ";
    private static final String NOMBRE_CLAVE = "clave_aes.key";
    private static final String EXTENSION_CIFRADO = ".cif";

    public static Path cifrar(String directorio) throws Exception {

        Path original = Paths.get(directorio);
        if (!Files.isRegularFile(original)) {
            throw new IllegalArgumentException("No existe el archivo a cifrar: " + original.toAbsolutePath());
        }

        // 1. Crear la carpeta general y la carpeta "Archivo N"
        Path general = Paths.get(CARPETA_GENERAL);
        Files.createDirectories(general);

        Path carpeta = general.resolve(PREFIJO_CARPETA + siguienteNumero(general));
        Files.createDirectories(carpeta);

        // 2. Generar clave AES y guardarla en la carpeta
        byte[] claveAES = GeneradorClaves.generarClaveAES128();
        Path archivoClave = carpeta.resolve(NOMBRE_CLAVE);
        Files.write(archivoClave, claveAES);
        System.out.println("Clave AES guardada en: " + archivoClave.toAbsolutePath());

        // 3. Cifrar (el IV queda al principio del archivo cifrado)
        Path cifrado = carpeta.resolve(original.getFileName().toString() + EXTENSION_CIFRADO);
        ProcesadorMultimedia.cifrarArchivo(original.toString(), cifrado.toString(), claveAES);

        return cifrado;
    }

    public static Path descifrar(String directorio) throws Exception {

        Path cifrado = Paths.get(directorio);
        if (!Files.isRegularFile(cifrado)) {
            throw new IllegalArgumentException("No existe el archivo cifrado: " + cifrado.toAbsolutePath());
        }

        // 1. Leer la clave desde la carpeta del archivo cifrado
        Path carpeta = cifrado.toAbsolutePath().getParent();
        Path archivoClave = carpeta.resolve(NOMBRE_CLAVE);
        if (!Files.isRegularFile(archivoClave)) {
            throw new IllegalStateException("No se encuentra la clave AES en: " + archivoClave);
        }
        byte[] claveLeida = Files.readAllBytes(archivoClave);

        // 2. Nombre de salida: quitamos ".cif" y añadimos "descifrado_"
        String nombre = cifrado.getFileName().toString();
        if (nombre.endsWith(EXTENSION_CIFRADO)) {
            nombre = nombre.substring(0, nombre.length() - EXTENSION_CIFRADO.length());
        }
        Path descifrado = carpeta.resolve("descifrado_" + nombre);

        // 3. Descifrar
        ProcesadorMultimedia.descifrarArchivo(cifrado.toString(), descifrado.toString(), claveLeida);

        return descifrado;
    }

    /** Devuelve el siguiente numero libre: si existen Archivo 1 y Archivo 2, devuelve 3. */
    private static int siguienteNumero(Path general) throws IOException {
        int max = 0;
        try (Stream<Path> hijos = Files.list(general)) {
            for (Path p : (Iterable<Path>) hijos::iterator) {
                String nombre = p.getFileName().toString();
                if (Files.isDirectory(p) && nombre.startsWith(PREFIJO_CARPETA)) {
                    try {
                        max = Math.max(max, Integer.parseInt(nombre.substring(PREFIJO_CARPETA.length())));
                    } catch (NumberFormatException e) {
                        // carpeta con otro formato: se ignora
                    }
                }
            }
        }
        return max + 1;
    }
}
