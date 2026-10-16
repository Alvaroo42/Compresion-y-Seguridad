package cliente.codificacion;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * Interfaz genérica para la codificación de datos.
 * Desacopla la lógica de la aplicación del algoritmo de codificación (ej. Base64).
 */
public interface Codificador {
    byte[] codificarABytes(byte[] datos);
    byte[] decodificarDeBytes(byte[] datosCodificados);
    
    String codificarAString(byte[] datos);
    byte[] decodificarDeString(String datosCodificados);
    
    OutputStream envolverSalida(OutputStream out);
    InputStream envolverEntrada(InputStream in);
}