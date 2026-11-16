package comun;

import java.io.IOException;
import java.io.StringReader;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Lo que cliente y servidor tienen que escribir exactamente igual: rutas de los endpoints, cabeceras,
 * nombres de los campos y reglas de validación. Los cuerpos de /REGISTRO y /LOGIN son texto clave=valor
 * (formato Properties) con los valores binarios en Base64, para no añadir librerías JSON.
 */
public final class Protocolo {

    private Protocolo() {
    }

    // ------------------------------------------------------------------ endpoints
    public static final String REGISTRO = "/REGISTRO";
    public static final String LOGIN = "/LOGIN";
    public static final String SUBIR = "/SUBIR";
    public static final String BAJAR = "/BAJAR";
    public static final String CLAVE_PUBLICA = "/CLAVE_PUBLICA";

    // ------------------------------------------------------------------ cabeceras
    public static final String CABECERA_AUTORIZACION = "Authorization";
    public static final String PREFIJO_BEARER = "Bearer ";
    public static final String CABECERA_NOMBRE = "Nombre";
    public static final String CABECERA_CLAVE_AES = "ClaveAESCifrada";
    public static final String CABECERA_DESTINATARIO = "Destinatario";
    public static final String CABECERA_FIRMA = "Firma";                    // mejora: firma digital del archivo
    public static final String CABECERA_REQUIERE_GOOGLE = "Requiere-Google"; // mejora: segundo factor con Google

    // ------------------------------------------------------------------ campos de los mensajes
    public static final String CAMPO_USUARIO = "usuario";
    public static final String CAMPO_CLAVE_LOGIN = "claveLogin";
    public static final String CAMPO_CLAVE_PUBLICA = "clavePublica";
    public static final String CAMPO_CLAVE_PRIVADA_CIFRADA = "clavePrivadaCifrada";
    public static final String CAMPO_TOKEN = "token";
    public static final String CAMPO_VALIDEZ_TOKEN = "validezTokenSegundos";
    public static final String CAMPO_ARCHIVOS = "archivos";
    public static final String PREFIJO_ARCHIVO = "archivo.";
    public static final String SUFIJO_ID = ".id";
    public static final String SUFIJO_NOMBRE = ".nombre";
    public static final String SUFIJO_CLAVE_AES = ".claveAESCifrada";
    public static final String SUFIJO_EMISOR = ".emisor";
    public static final String SUFIJO_FIRMA = ".firma";
    public static final String CAMPO_ID_TOKEN_GOOGLE = "idTokenGoogle";
    public static final String CAMPO_NONCE_GOOGLE = "nonceGoogle";
    public static final String CAMPO_CORREO_GOOGLE = "correoGoogle";

    // Parámetros de las URL (?id=... y ?usuario=...)
    public static final String PARAM_ID = "id";
    public static final String PARAM_USUARIO = "usuario";

    // ------------------------------------------------------------------ límites
    public static final int LONGITUD_MIN_CONTRASENA = 8;
    public static final int TAM_CLAVE_LOGIN = 16;
    public static final int MAX_CUERPO_TEXTO = 64 * 1024;

    // ------------------------------------------------------------------ validación
    private static final Pattern PATRON_USUARIO = Pattern.compile("[A-Za-z0-9_.-]{3,32}");
    private static final Pattern PATRON_ID = Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    private static final Set<String> NOMBRES_RESERVADOS_WINDOWS = Set.of("CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9");

    // Mismo patrón en cliente y servidor: [A-Za-z0-9_.-]{3,32}. Además no puede empezar ni acabar en punto
    // (Windows quita los puntos finales de las carpetas, "..." sería la carpeta padre) ni ser un nombre
    // reservado de Windows como CON o NUL, porque el nombre se usa como carpeta en el servidor.
    public static boolean usuarioValido(String usuario) {
        if (usuario == null || !PATRON_USUARIO.matcher(usuario).matches() || usuario.startsWith(".") || usuario.endsWith(".")) {
            return false;
        }
        String base = usuario.toUpperCase(Locale.ROOT);
        int punto = base.indexOf('.');
        return !NOMBRES_RESERVADOS_WINDOWS.contains(punto >= 0 ? base.substring(0, punto) : base);
    }

    // Los id de archivo son UUID generados por el servidor
    public static boolean idValido(String id) {
        return id != null && PATRON_ID.matcher(id).matches();
    }

    // ------------------------------------------------------------------ formato clave=valor

    // Escribe los campos en el orden en que se añadieron, una línea "clave=valor" por campo
    public static String escribir(Map<String, String> campos) {
        StringBuilder texto = new StringBuilder();
        for (Map.Entry<String, String> campo : campos.entrySet()) {
            String valor = campo.getValue();
            if (valor.indexOf('\n') >= 0 || valor.indexOf('\r') >= 0 || valor.indexOf('\\') >= 0) {
                throw new IllegalArgumentException("Valor no válido en el campo " + campo.getKey());
            }
            texto.append(campo.getKey()).append('=').append(valor).append('\n');
        }
        return texto.toString();
    }

    public static Properties leer(String texto) {
        Properties propiedades = new Properties();
        try {
            propiedades.load(new StringReader(texto));
        } catch (IOException | IllegalArgumentException e) {
            throw new IllegalArgumentException("Mensaje con formato no válido");
        }
        return propiedades;
    }
}
