package cliente.servicio;

import cliente.servicio.ServicioCifrado.DetalleArchivo;

import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.List;

public class SesionLocal implements AutoCloseable {

    private final ServicioCifrado servicio = new ServicioCifrado();
    private String usuario;
    private PrivateKey clavePrivada;

    // Registra el usuario y la contraseña
    public void registrar(String usuario, char[] contrasena) throws GeneralSecurityException, IOException {
        servicio.registrarUsuario(usuario, contrasena);
    }

    // Guardar nombre en usuario y crear clave privada
    public void iniciarSesion(String usuario, char[] contrasena) throws GeneralSecurityException, IOException {
        this.clavePrivada = servicio.iniciarSesion(usuario, contrasena);
        this.usuario = usuario;
    }

    // Cifra el archivo ubicado en el directorio
    public String cifrar(Path archivo) throws GeneralSecurityException, IOException {
        exigirSesion();
        return servicio.cifrarArchivo(usuario, archivo);
    }

    // Lista de archivos cifrados de este usuario
    public List<DetalleArchivo> listar() throws IOException {
        exigirSesion();
        return servicio.listarDetalle(usuario);
    }

    // Descifrar archivo especifico 
    public Path descifrar(String idArchivo, Path carpetaDestino) throws GeneralSecurityException, IOException {
        exigirSesion();
        return servicio.descifrarArchivo(usuario, clavePrivada, idArchivo, carpetaDestino);
    }

    // Get nombre usuario 
    public String getUsuario() {
        return usuario;
    }

    // Vacia la clave privada de la sesion local
    @Override
    public void close() {
        clavePrivada = null;
    }

    // Excepcion para cuando no existe clave privada
    private void exigirSesion() {
        if (clavePrivada == null) {
            throw new IllegalStateException("Primero hay que iniciar sesión");
        }
    }
}