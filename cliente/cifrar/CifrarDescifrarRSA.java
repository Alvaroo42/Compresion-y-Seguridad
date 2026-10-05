package cliente.cifrar;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.stream.Stream;

import cliente.almacenamiento.ProcesadorMultimedia;
import cliente.criptografia.CifradoRSA;
import cliente.criptografia.GeneradorClaves;


public class CifrarDescifrarRSA {

    private static final String CARPETA_GENERAL = "almacenamiento_general";
    private static final String PREFIJO_CARPETA = "Archivo ";
    private static final String EXTENSION_CIFRADO = ".cif";
    private static final String NOMBRE_CLAVE_AES_CIFRADA = "clave_aes.cif";
    private static final String NOMBRE_CLAVE_PUBLICA = "clave_publica.key";
    private static final String NOMBRE_CLAVE_PRIVADA = "clave_privada.key";


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

        // 2. Generar la clave AES y el par de claves RSA
        byte[] claveAES = GeneradorClaves.generarClaveAES128();
        KeyPair parRSA = CifradoRSA.generarParClaves();

        // 3. Cifrar el archivo con AES (el IV queda al principio del .cif)
        Path cifrado = carpeta.resolve(original.getFileName().toString() + EXTENSION_CIFRADO);
        ProcesadorMultimedia.cifrarArchivo(original.toString(), cifrado.toString(), claveAES);

        // 4. Cifrar la clave AES con la clave publica RSA y guardarla
        byte[] claveAESCifrada = CifradoRSA.cifrarClaveAES(claveAES, parRSA.getPublic());
        Path archivoClaveAES = carpeta.resolve(NOMBRE_CLAVE_AES_CIFRADA);
        Files.write(archivoClaveAES, claveAESCifrada);
        System.out.println("Clave AES cifrada con RSA guardada en: " + archivoClaveAES.toAbsolutePath());

        // 5. Guardar las claves RSA en la misma carpeta
        Path archivoPublica = carpeta.resolve(NOMBRE_CLAVE_PUBLICA);
        Path archivoPrivada = carpeta.resolve(NOMBRE_CLAVE_PRIVADA);
        Files.write(archivoPublica, parRSA.getPublic().getEncoded());
        Files.write(archivoPrivada, parRSA.getPrivate().getEncoded());
        System.out.println("Claves RSA guardadas en: " + carpeta.toAbsolutePath());

        return cifrado;
    }

    public static Path descifrar(String directorio) throws Exception {

        Path cifrado = Paths.get(directorio);
        if (!Files.isRegularFile(cifrado)) {
            throw new IllegalArgumentException("No existe el archivo cifrado: " + cifrado.toAbsolutePath());
        }
        Path carpeta = cifrado.toAbsolutePath().getParent();

        Path archivoPrivada = carpeta.resolve(NOMBRE_CLAVE_PRIVADA);
        Path archivoClaveAES = carpeta.resolve(NOMBRE_CLAVE_AES_CIFRADA);
        if (!Files.isRegularFile(archivoPrivada) || !Files.isRegularFile(archivoClaveAES)) {
            throw new IllegalStateException("Faltan " + NOMBRE_CLAVE_PRIVADA + " o "
                    + NOMBRE_CLAVE_AES_CIFRADA + " en: " + carpeta);
        }

        // 1. Recuperar la clave privada RSA
        PrivateKey clavePrivada = KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(archivoPrivada)));

        // 2. Descifrar la clave AES con la clave privada RSA
        byte[] claveAES = CifradoRSA.descifrarClaveAES(Files.readAllBytes(archivoClaveAES), clavePrivada);

        // 3. Nombre de salida: quitamos ".cif" y anadimos "descifrado_"
        String nombre = cifrado.getFileName().toString();
        if (nombre.endsWith(EXTENSION_CIFRADO)) {
            nombre = nombre.substring(0, nombre.length() - EXTENSION_CIFRADO.length());
        }
        Path descifrado = carpeta.resolve("descifrado_" + nombre);

        // 4. Descifrar el archivo con la clave AES recuperada
        ProcesadorMultimedia.descifrarArchivo(cifrado.toString(), descifrado.toString(), claveAES);

        return descifrado;
    }

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
