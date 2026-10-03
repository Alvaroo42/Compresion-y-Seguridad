package cliente.almacenamiento;

import cliente.criptografia.CifradorAES;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class ProcesadorMultimedia {

    public static void cifrarArchivo(String rutaOrigen, String rutaDestino, byte[] claveAES) throws Exception {
        // Leer archivo multimedia completo
        Path pathOrigen = Paths.get(rutaOrigen);
        byte[] datosEnClaro = Files.readAllBytes(pathOrigen);
        
        // Cifrar los datos utilizando vuestra clase existente
        byte[] datosCifrados = CifradorAES.cifrar(datosEnClaro, claveAES);
        
        // Escribir el resultado en el disco
        Path pathDestino = Paths.get(rutaDestino);
        Files.write(pathDestino, datosCifrados);
        
        System.out.println("Archivo cifrado correctamente en: " + pathDestino.toAbsolutePath());
    }

    public static void descifrarArchivo(String rutaCifrado, String rutaDestinoOriginal, byte[] claveAES) throws Exception {
        // Leer el archivo cifrado (incluye el IV al principio gracias a vuestro CifradorAES)
        Path pathCifrado = Paths.get(rutaCifrado);
        byte[] datosCifrados = Files.readAllBytes(pathCifrado);
        
        // Descifrar obteniendo los bytes del multimedia original
        byte[] datosDescifrados = CifradorAES.descifrar(datosCifrados, claveAES);
        
        // Escribir el archivo multimedia para poder reproducirlo/abrirlo
        Path pathDestino = Paths.get(rutaDestinoOriginal);
        Files.write(pathDestino, datosDescifrados);
        
        System.out.println("Archivo recuperado correctamente en: " + pathDestino.toAbsolutePath());
    }
}