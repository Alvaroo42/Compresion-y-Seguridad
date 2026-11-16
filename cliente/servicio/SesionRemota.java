package cliente.servicio;

import cliente.google.CredencialGoogle;
import cliente.red.ClienteServidor;
import cliente.servicio.ServicioCifrado.DatosSesion;
import cliente.servicio.ServicioCifrado.DetalleArchivo;

import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Sesión de un usuario (antes SesionLocal). Guarda SOLO en memoria el token y la clave privada mientras dura
 * la sesión; es lo único que usa la interfaz. Al cerrar la sesión se borran (7.6).
 */
public class SesionRemota implements AutoCloseable {

    private final ServicioCifrado servicio;
    private String usuario;
    private String token;
    private Instant caducidad;
    private PrivateKey clavePrivada;
    private PublicKey clavePublica;
    private String correoGoogle;
    private final List<DetalleArchivo> archivos = new ArrayList<>();

    public SesionRemota(ServicioCifrado servicio) {
        this.servicio = servicio;
    }

    public void registrar(String usuario, char[] contrasena, CredencialGoogle google) throws GeneralSecurityException, IOException {
        servicio.registrarUsuario(usuario, contrasena, google);
    }

    // Inicia sesión y devuelve los archivos del usuario (los suyos y los que le han compartido)
    public List<DetalleArchivo> iniciarSesion(String usuario, char[] contrasena, CredencialGoogle google) throws GeneralSecurityException, IOException {
        DatosSesion datos = servicio.iniciarSesion(usuario, contrasena, google);
        this.usuario = usuario;
        this.token = datos.token();
        this.caducidad = datos.caducidad();
        this.clavePrivada = datos.clavePrivada();
        this.clavePublica = datos.clavePublica();
        this.correoGoogle = datos.correoGoogle();
        archivos.clear();
        archivos.addAll(datos.archivos());
        return listar();
    }

    // Cifra un archivo y lo sube; se añade a la lista sin volver a pedirla al servidor
    public DetalleArchivo cifrar(Path archivo) throws GeneralSecurityException, IOException {
        exigirSesion();
        DetalleArchivo nuevo = servicio.cifrarYSubir(token, usuario, clavePrivada, clavePublica, archivo);
        archivos.add(nuevo);
        return nuevo;
    }

    public List<DetalleArchivo> listar() {
        return List.copyOf(archivos);
    }

    public Path descifrar(DetalleArchivo archivo, Path carpetaDestino) throws GeneralSecurityException, IOException {
        exigirSesion();
        return servicio.descifrarArchivo(token, usuario, clavePrivada, clavePublica, archivo, carpetaDestino);
    }

    public void compartir(DetalleArchivo archivo, String destinatario) throws GeneralSecurityException, IOException {
        exigirSesion();
        servicio.compartirArchivo(token, usuario, clavePrivada, clavePublica, archivo, destinatario);
    }

    public String getUsuario() {
        return usuario;
    }

    // Correo de Google si la cuenta está protegida con Google (o null)
    public String getCorreoGoogle() {
        return correoGoogle;
    }

    // 7.6 Cerrar sesión: se borran de memoria el token y las claves
    @Override
    public void close() {
        token = null;
        caducidad = null;
        clavePrivada = null;
        clavePublica = null;
        correoGoogle = null;
        archivos.clear();
    }

    private void exigirSesion() throws ClienteServidor.ErrorServidor {
        if (clavePrivada == null || token == null) {
            throw new IllegalStateException("Primero hay que iniciar sesión");
        }
        // El servidor da tokens de 30 minutos: si ya ha caducado no tiene sentido empezar una subida
        if (Instant.now().isAfter(caducidad)) {
            throw new ClienteServidor.ErrorServidor(401, "La sesión ha caducado", false);
        }
    }
}
