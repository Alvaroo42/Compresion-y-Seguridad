package cliente;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

import cliente.almacenamiento.ProcesadorMultimedia;
import cliente.criptografia.GeneradorClaves;

/**
 * Prueba local: cifra un archivo de texto con AES-128 (CTR), guarda la clave y
 * el archivo cifrado en una carpeta, y despues los lee de disco para descifrar.
 *
 * Uso:
 *   java cliente.PruebaAES                -> crea un texto de ejemplo y lo cifra
 *   java cliente.PruebaAES ruta/texto.txt -> cifra ese archivo
 */
public class PruebaAES {

    private static final String CARPETA = "prueba_aes";

    public static void main(String[] args) throws Exception {

        Path carpeta = Paths.get(CARPETA);
        Files.createDirectories(carpeta);

        // 1. Archivo de texto de origen
        Path original;
        if (args.length > 0) {
            original = Paths.get(args[0]);
        } else {
            original = carpeta.resolve("original.txt");
            String texto = "Hola, este es un archivo de texto de prueba.\n"
                         + "Lo vamos a cifrar con AES-128 en modo CTR.\n";
            Files.write(original, texto.getBytes(StandardCharsets.UTF_8));
        }
        System.out.println("Archivo original: " + original.toAbsolutePath());

        // 2. Generar clave AES y guardarla en la carpeta
        byte[] claveAES = GeneradorClaves.generarClaveAES128();
        Path archivoClave = carpeta.resolve("clave_aes.key");
        Files.write(archivoClave, claveAES);
        System.out.println("Clave AES guardada en: " + archivoClave.toAbsolutePath());

        // 3. Cifrar (el IV queda al principio del archivo cifrado)
        Path cifrado = carpeta.resolve("texto.cif");
        ProcesadorMultimedia.cifrarArchivo(original.toString(), cifrado.toString(), claveAES);

        // 4. Descifrar leyendo la clave y el cifrado desde disco
        byte[] claveLeida = Files.readAllBytes(archivoClave);
        Path descifrado = carpeta.resolve("descifrado.txt");
        ProcesadorMultimedia.descifrarArchivo(cifrado.toString(), descifrado.toString(), claveLeida);

        // 5. Comprobar que coincide con el original
        boolean iguales = Arrays.equals(Files.readAllBytes(original), Files.readAllBytes(descifrado));
        System.out.println(iguales
                ? "OK: el archivo descifrado coincide con el original."
                : "ERROR: el archivo descifrado NO coincide con el original.");
    }
}
