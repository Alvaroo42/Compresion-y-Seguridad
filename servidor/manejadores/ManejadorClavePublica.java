package servidor.manejadores;

import com.sun.net.httpserver.HttpExchange;
import comun.Protocolo;
import servidor.almacenamiento.AlmacenUsuarios;
import servidor.seguridad.GestorTokens;

import java.util.Properties;

/**
 * GET /CLAVE_PUBLICA?usuario=<destinatario> (protegido con token). Devuelve la clave pública (X.509 en Base64)
 * del destinatario, que el cliente necesita para compartir. 404 si el usuario no existe.
 */
public class ManejadorClavePublica extends ManejadorBase {

    public ManejadorClavePublica(AlmacenUsuarios almacen, GestorTokens tokens) {
        super("GET", almacen, tokens);
    }

    @Override
    protected void procesar(HttpExchange ex) throws Exception {
        usuarioDelToken(ex);
        String usuario = parametro(ex, Protocolo.PARAM_USUARIO);
        Properties perfil = Protocolo.usuarioValido(usuario) ? almacen.leerPerfil(usuario) : null;
        if (perfil == null) {
            throw new ErrorHttp(404, "El usuario no existe");
        }
        responderTexto(ex, 200, perfil.getProperty("clavePublica"));
    }
}
