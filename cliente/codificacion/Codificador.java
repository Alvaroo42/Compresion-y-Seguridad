package cliente.codificacion;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Base64;

public class Codificador {

    private static final int TAM_BUFFER = 64 * 1024;

    // Codificar en base64 a bytes
    public byte[] codificarABytes(byte[] datos) {
        if (datos == null)
            return null;
        return Base64.getEncoder().encode(datos);
    }

    // Decodificar en base64 a bytes
    public byte[] decodificarDeBytes(byte[] datosCodificados) {
        if (datosCodificados == null) 
            return null;
        return Base64.getDecoder().decode(datosCodificados);
    }

    // Codificar en base64 a strings
    public String codificarAString(byte[] datos) {
        if (datos == null) 
            return null;
        return Base64.getEncoder().encodeToString(datos);
    }

    // Decodificar en base64 a strings
    public byte[] decodificarDeString(String datosCodificados) {
        if (datosCodificados == null) 
            return null;
        return Base64.getDecoder().decode(datosCodificados);
    }


    // Lo que se escriba en el flujo devuelto sale codificado hacia 'out'
    public OutputStream envolverSalida(OutputStream out) {
        return Base64.getEncoder().wrap(new BufferedOutputStream(out, TAM_BUFFER));
    }

    // Lo que se lea del flujo devuelto es el contenido de 'in' ya decodificado
    public InputStream envolverEntrada(InputStream in) {
        return Base64.getDecoder().wrap(new BufferedInputStream(in, TAM_BUFFER));
    }
}