package cliente.servicio;

import cliente.servicio.ServicioCifrado.DetalleArchivo;

import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.List;

/**
 * Sesión de un usuario sobre ServicioCifrado. La interfaz sólo habla con esta clase.
 *
 * Tras iniciarSesion la clave privada queda SÓLO en memoria; ni la contraseña ni la clave
 * privada en claro se guardan. close() olvida la clave privada.
 */
public class SesionLocal implements AutoCloseable {

    private final ServicioCifrado servicio = new ServicioCifrado();
    private String usuario;
    private PrivateKey clavePrivada;

    /** Da de alta al usuario (genera su par RSA). Después hay que llamar a iniciarSesion. */
    public void registrar(String usuario, char[] contrasena) throws GeneralSecurityException, IOException {
        servicio.registrarUsuario(usuario, contrasena);
    }

    /** Recupera la clave privada con la contraseña. Lanza ContrasenaIncorrectaException si no coincide. */
    public void iniciarSesion(String usuario, char[] contrasena) throws GeneralSecurityException, IOException {
        this.clavePrivada = servicio.iniciarSesion(usuario, contrasena);
        this.usuario = usuario;
    }

    /** Cifra un archivo con una clave AES nueva y lo guarda. Devuelve su id. */
    public String cifrar(Path archivo) throws GeneralSecurityException, IOException {
        exigirSesion();
        return servicio.cifrarArchivo(usuario, archivo);
    }

    public List<DetalleArchivo> listar() throws IOException {
        exigirSesion();
        return servicio.listarDetalle(usuario);
    }

    /** Descifra el archivo y lo deja en 'carpetaDestino'. Devuelve la ruta creada. */
    public Path descifrar(String idArchivo, Path carpetaDestino) throws GeneralSecurityException, IOException {
        exigirSesion();
        return servicio.descifrarArchivo(usuario, clavePrivada, idArchivo, carpetaDestino);
    }

    public String getUsuario() {
        return usuario;
    }

    @Override
    public void close() {
        clavePrivada = null;
    }

    private void exigirSesion() {
        if (clavePrivada == null) {
            throw new IllegalStateException("Primero hay que iniciar sesión");
        }
    }
}