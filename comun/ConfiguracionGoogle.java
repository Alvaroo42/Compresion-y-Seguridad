package comun;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

/**
 * Configuración del inicio de sesión con Google (mejora). Se lee de google_oauth.properties, que NO se sube al
 * repositorio. Cada grupo crea su propio "ID de cliente OAuth" de tipo "Aplicación de escritorio" en Google Cloud:
 *
 *   clientId=1234-abc.apps.googleusercontent.com
 *   clientSecret=GOCSPX-...
 *
 * Las direcciones de Google tienen valor por defecto; solo se cambian para las pruebas automáticas, que usan un
 * proveedor de prueba local que firma los tokens igual que Google.
 */
public record ConfiguracionGoogle(String clientId, String clientSecret, String authUri, String tokenUri, String jwksUri) {

    public static final String ARCHIVO_POR_DEFECTO = "google_oauth.properties";
    public static final String AUTH_GOOGLE = "https://accounts.google.com/o/oauth2/v2/auth";
    public static final String TOKEN_GOOGLE = "https://oauth2.googleapis.com/token";
    public static final String JWKS_GOOGLE = "https://www.googleapis.com/oauth2/v3/certs";

    // Ruta del fichero: -Dcys.google=<ruta> o google_oauth.properties en la carpeta del programa
    public static Path ruta() {
        return Path.of(System.getProperty("cys.google", ARCHIVO_POR_DEFECTO));
    }

    // Lee la configuración; devuelve null si el fichero no existe o no tiene clientId (Google desactivado)
    public static ConfiguracionGoogle cargar(Path archivo) throws IOException {
        if (!Files.isRegularFile(archivo)) {
            return null;
        }
        Properties p = new Properties();
        try (Reader lector = Files.newBufferedReader(archivo, StandardCharsets.UTF_8)) {
            p.load(lector);
        }
        String clientId = p.getProperty("clientId", "").trim();
        if (clientId.isEmpty()) {
            return null;
        }
        return new ConfiguracionGoogle(clientId, p.getProperty("clientSecret", "").trim(),
                p.getProperty("authUri", AUTH_GOOGLE).trim(), p.getProperty("tokenUri", TOKEN_GOOGLE).trim(),
                p.getProperty("jwksUri", JWKS_GOOGLE).trim());
    }
}
