package servidor.manejadores;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import comun.Protocolo;
import servidor.almacenamiento.AlmacenUsuarios;
import servidor.seguridad.GestorTokens;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Properties;

/**
 * Lo común a todos los endpoints: método HTTP permitido, autenticación con el token, lectura de cuerpos con
 * límite de tamaño y respuestas. Los errores se responden con un mensaje genérico; los detalles internos se
 * quedan en la consola del servidor.
 */
public abstract class ManejadorBase implements HttpHandler {

    protected final AlmacenUsuarios almacen;
    protected final GestorTokens tokens;
    private final String metodo;

    protected ManejadorBase(String metodo, AlmacenUsuarios almacen, GestorTokens tokens) {
        this.metodo = metodo;
        this.almacen = almacen;
        this.tokens = tokens;
    }

    protected abstract void procesar(HttpExchange ex) throws Exception;

    @Override
    public final void handle(HttpExchange ex) throws IOException {
        try {
            if (!metodo.equals(ex.getRequestMethod())) {
                throw new ErrorHttp(405, "Método no permitido");
            }
            procesar(ex);
        } catch (ErrorHttp e) {
            vaciarCuerpo(ex);
            if (e.cabecera() != null) {
                ex.getResponseHeaders().set(e.cabecera(), e.valorCabecera());
            }
            responderTexto(ex, e.estado(), e.getMessage());
        } catch (Exception e) {
            System.err.println("Error interno en " + ex.getRequestURI().getPath() + ": " + e);
            vaciarCuerpo(ex);
            responderTexto(ex, 500, "Error interno del servidor");
        } finally {
            System.out.printf("%s %s -> %d%n", ex.getRequestMethod(), ex.getRequestURI().getPath(), ex.getResponseCode());
            ex.close();
        }
    }

    // ------------------------------------------------------------------ autenticación

    // Usuario del token de "Authorization: Bearer <token>". El usuario sale siempre del token, nunca de un parámetro.
    protected String usuarioDelToken(HttpExchange ex) throws ErrorHttp {
        String cabecera = ex.getRequestHeaders().getFirst(Protocolo.CABECERA_AUTORIZACION);
        String token = cabecera != null && cabecera.startsWith(Protocolo.PREFIJO_BEARER)
                ? cabecera.substring(Protocolo.PREFIJO_BEARER.length()).trim() : null;
        String usuario = tokens.usuarioDe(token);
        if (usuario == null) {
            throw new ErrorHttp(401, "Falta el token de sesión o ha caducado");
        }
        return usuario;
    }

    // ------------------------------------------------------------------ peticiones

    // Cuerpo clave=valor de /REGISTRO y /LOGIN (máximo 64 KB)
    protected Properties leerCampos(HttpExchange ex) throws IOException, ErrorHttp {
        ByteArrayOutputStream cuerpo = new ByteArrayOutputStream();
        try (InputStream in = ex.getRequestBody()) {
            byte[] buffer = new byte[8192];
            int leidos;
            while ((leidos = in.read(buffer)) != -1) {
                if (cuerpo.size() + leidos > Protocolo.MAX_CUERPO_TEXTO) {
                    throw new ErrorHttp(413, "Petición demasiado grande");
                }
                cuerpo.write(buffer, 0, leidos);
            }
        }
        try {
            return Protocolo.leer(cuerpo.toString(StandardCharsets.UTF_8));
        } catch (IllegalArgumentException e) {
            throw new ErrorHttp(400, "Petición no válida");
        }
    }

    // Campo obligatorio en Base64 con un tamaño entre min y max bytes
    protected static byte[] binario(String valor, int min, int max) throws ErrorHttp {
        if (valor == null) {
            throw new ErrorHttp(400, "Petición no válida");
        }
        try {
            byte[] bytes = Base64.getDecoder().decode(valor.trim());
            if (bytes.length < min || bytes.length > max) {
                throw new ErrorHttp(400, "Petición no válida");
            }
            return bytes;
        } catch (IllegalArgumentException e) {
            throw new ErrorHttp(400, "Petición no válida");
        }
    }

    // Parámetro de la URL (?id=...&usuario=...)
    protected static String parametro(HttpExchange ex, String nombre) {
        String consulta = ex.getRequestURI().getRawQuery();
        if (consulta == null) {
            return null;
        }
        for (String par : consulta.split("&")) {
            int igual = par.indexOf('=');
            if (igual > 0 && URLDecoder.decode(par.substring(0, igual), StandardCharsets.UTF_8).equals(nombre)) {
                return URLDecoder.decode(par.substring(igual + 1), StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    // ------------------------------------------------------------------ respuestas

    protected static void responderTexto(HttpExchange ex, int estado, String texto) throws IOException {
        byte[] cuerpo = texto.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        ex.sendResponseHeaders(estado, cuerpo.length == 0 ? -1 : cuerpo.length);
        if (cuerpo.length > 0) {
            try (OutputStream out = ex.getResponseBody()) {
                out.write(cuerpo);
            }
        }
    }

    protected static void responderCampos(HttpExchange ex, int estado, Map<String, String> campos) throws IOException {
        responderTexto(ex, estado, Protocolo.escribir(campos));
    }

    // Si se responde un error sin haber leído el cuerpo, el cliente puede ver un corte de conexión en vez del
    // error. Se descarta lo que haya llegado, con un tope para no malgastar recursos.
    private static void vaciarCuerpo(HttpExchange ex) {
        try (InputStream in = ex.getRequestBody()) {
            byte[] basura = new byte[8192];
            long restante = 1L << 20;
            int leidos;
            while (restante > 0 && (leidos = in.read(basura, 0, (int) Math.min(basura.length, restante))) != -1) {
                restante -= leidos;
            }
        } catch (IOException e) {
            // el cliente ya ha cortado
        }
    }
}
