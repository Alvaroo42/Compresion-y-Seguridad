package servidor.manejadores;

import com.sun.net.httpserver.HttpExchange;
import comun.Protocolo;
import servidor.almacenamiento.AlmacenUsuarios;
import servidor.seguridad.GestorTokens;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * POST /SUBIR (protegido con token). Cuerpo = bytes del .cif; cabeceras Nombre, ClaveAESCifrada y, opcional,
 * Destinatario (y Firma, mejora). Sin destinatario se guarda en la carpeta del usuario del token; con
 * destinatario, en la carpeta del destinatario con emisor = usuario del token. El servidor solo comprueba que
 * el destinatario existe: no puede leer nada. Responde 201 con el id del archivo.
 */
public class ManejadorSubir extends ManejadorBase {

    private static final long TAM_MAXIMO = 4L * 1024 * 1024 * 1024;

    public ManejadorSubir(AlmacenUsuarios almacen, GestorTokens tokens) {
        super("POST", almacen, tokens);
    }

    @Override
    protected void procesar(HttpExchange ex) throws Exception {
        String emisor = usuarioDelToken(ex);
        String nombre = ex.getRequestHeaders().getFirst(Protocolo.CABECERA_NOMBRE);
        binario(nombre, 1, 4096);   // el nombre llega en Base64 (cifrado por el cliente)
        byte[] claveAES = binario(ex.getRequestHeaders().getFirst(Protocolo.CABECERA_CLAVE_AES), 1, 1024);
        String firma = ex.getRequestHeaders().getFirst(Protocolo.CABECERA_FIRMA);
        if (firma != null) {
            binario(firma, 1, 1024);
        }

        String propietario = emisor;
        String destinatario = ex.getRequestHeaders().getFirst(Protocolo.CABECERA_DESTINATARIO);
        if (destinatario != null) {
            if (!almacen.existe(destinatario)) {
                throw new ErrorHttp(404, "El usuario destinatario no existe");
            }
            if (destinatario.equals(emisor)) {
                throw new ErrorHttp(400, "No puedes compartir un archivo contigo mismo");
            }
            propietario = destinatario;
        }

        Path temporal = almacen.nuevoTemporal(propietario);
        try {
            recibir(ex.getRequestBody(), temporal);
            Map<String, String> meta = new LinkedHashMap<>();
            meta.put("nombre", nombre.trim());
            meta.put("claveAESCifrada", Base64.getEncoder().encodeToString(claveAES));
            meta.put("emisor", emisor);
            if (firma != null) {
                meta.put("firma", firma.trim());
            }
            String id = almacen.guardarArchivo(propietario, temporal, meta);
            responderTexto(ex, 201, id);
        } finally {
            Files.deleteIfExists(temporal);
        }
    }

    // Copia el cuerpo al temporal por bloques de 64 KB (vídeos de varios GB sin cargarlos en memoria)
    private static void recibir(InputStream entrada, Path temporal) throws Exception {
        long total = 0;
        byte[] buffer = new byte[64 * 1024];
        try (InputStream in = entrada; OutputStream out = Files.newOutputStream(temporal)) {
            int leidos;
            while ((leidos = in.read(buffer)) != -1) {
                total += leidos;
                if (total > TAM_MAXIMO) {
                    throw new ErrorHttp(413, "Archivo demasiado grande");
                }
                out.write(buffer, 0, leidos);
            }
        }
        if (total == 0) {
            throw new ErrorHttp(400, "El archivo está vacío");
        }
    }
}
