package cliente.codificacion;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.Base64;

public class CodificadorBase64 implements Codificador {

    @Override
    public byte[] codificarABytes(byte[] datos) {
        if (datos == null) return null;
        return Base64.getEncoder().encode(datos);
    }

    @Override
    public byte[] decodificarDeBytes(byte[] datosCodificados) {
        if (datosCodificados == null) return null;
        return Base64.getDecoder().decode(datosCodificados);
    }

    @Override
    public String codificarAString(byte[] datos) {
        if (datos == null) return null;
        return Base64.getEncoder().encodeToString(datos);
    }

    @Override
    public byte[] decodificarDeString(String datosCodificados) {
        if (datosCodificados == null) return null;
        return Base64.getDecoder().decode(datosCodificados);
    }

    @Override
    public OutputStream envolverSalida(OutputStream out) {
        return Base64.getEncoder().wrap(out);
    }

    @Override
    public InputStream envolverEntrada(InputStream in) {
        return Base64.getDecoder().wrap(in);
    }
}