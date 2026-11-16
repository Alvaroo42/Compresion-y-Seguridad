package servidor.manejadores;

import com.sun.net.httpserver.HttpExchange;
import comun.Protocolo;
import servidor.almacenamiento.AlmacenUsuarios;
import servidor.seguridad.GestorTokens;

import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * GET /BAJAR?id=<id> (protegido con token). Devuelve los bytes del .cif. El archivo se busca SOLO en la
 * carpeta del usuario del token: si el id es de otro usuario (o no existe) responde 404.
 */
public class ManejadorBajar extends ManejadorBase {

    public ManejadorBajar(AlmacenUsuarios almacen, GestorTokens tokens) {
        super("GET", almacen, tokens);
    }

    @Override
    protected void procesar(HttpExchange ex) throws Exception {
        String usuario = usuarioDelToken(ex);
        Path cif = almacen.rutaCif(usuario, parametro(ex, Protocolo.PARAM_ID));
        if (cif == null) {
            throw new ErrorHttp(404, "Archivo no encontrado");
        }
        ex.getResponseHeaders().set("Content-Type", "application/octet-stream");
        ex.sendResponseHeaders(200, Files.size(cif));
        try (OutputStream out = ex.getResponseBody()) {
            Files.copy(cif, out);
        }
    }
}
