package cliente.servicio;

import cliente.almacenamiento.GestorFicheros;
import cliente.criptografia.CifradoRSA;
import cliente.criptografia.CifradorAES;
import cliente.criptografia.ProtectorClavePrivada;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;

public class ServicioCifrado {

    private static final Pattern NOMBRE_VALIDO = Pattern.compile("[A-Za-z0-9_.-]{3,32}");
    private static final int LONGITUD_MIN_CONTRASENA = 4;

    /** Un archivo cifrado de la lista (la interfaz muestra su nombre original). */
    public record DetalleArchivo(String id, String nombre) {
        @Override
        public String toString() {
            return nombre;
        }
    }

    // ------------------------------------------------------------------
    // Alta de usuario (genera y guarda su par RSA)
    // ------------------------------------------------------------------

    public void registrarUsuario(String usuario, char[] contrasena) throws GeneralSecurityException, IOException {
        if (!NOMBRE_VALIDO.matcher(usuario).matches()) {
            throw new IllegalArgumentException("Nombre de usuario no válido (3-32 caracteres)");
        }
        if (contrasena.length < LONGITUD_MIN_CONTRASENA) {
            throw new IllegalArgumentException("La contraseña debe tener al menos " + LONGITUD_MIN_CONTRASENA + " caracteres");
        }
        if (GestorFicheros.existeUsuario(usuario)) {
            throw new IllegalArgumentException("El usuario '" + usuario + "' ya existe");
        }

        KeyPair par = CifradoRSA.generarParClaves();
        byte[] privadaProtegida = ProtectorClavePrivada.proteger(par.getPrivate(), contrasena);
        GestorFicheros.guardarClavesUsuario(usuario, par.getPublic().getEncoded(), privadaProtegida);
    }

    /** Recupera la clave privada del usuario con su contraseña. */
    public PrivateKey iniciarSesion(String usuario, char[] contrasena) throws IOException, GeneralSecurityException {
        comprobarUsuarioExiste(usuario);
        return ProtectorClavePrivada.recuperar(GestorFicheros.leerClavePrivadaCifrada(usuario), contrasena);
    }

    // ------------------------------------------------------------------
    // Cifrado de un archivo multimedia
    // ------------------------------------------------------------------

    public String cifrarArchivo(String usuario, Path archivo) throws GeneralSecurityException, IOException {
        comprobarUsuarioExiste(usuario);
        if (!Files.isRegularFile(archivo)) {
            throw new IllegalArgumentException("No existe el archivo: " + archivo);
        }

        PublicKey pu = CifradoRSA.cargarClavePublica(GestorFicheros.leerClavePublica(usuario));
        byte[] k = CifradorAES.generarClaveAES();             // clave AES nueva para este archivo
        String id = UUID.randomUUID().toString();

        try {
            // 1. Se cifra el archivo con K
            try (InputStream in = Files.newInputStream(archivo);
                 OutputStream outCifrado = GestorFicheros.obtenerFlujoSalidaCifrado(id)) {
                CifradorAES.cifrarFlujo(in, outCifrado, k);
            }
            // 2. Se cifra K con la clave pública y se guarda junto al nombre original
            byte[] kCifrada = CifradoRSA.cifrarClaveAES(k, pu);
            GestorFicheros.guardarMetadatosArchivo(id, usuario, archivo.getFileName().toString(), kCifrada);
        } catch (GeneralSecurityException | IOException ex) {
            // Si algo falla, no se deja ningún archivo a medias
            Files.deleteIfExists(GestorFicheros.rutaArchivoCifrado(id));
            Files.deleteIfExists(GestorFicheros.directorioCifrados().resolve(id + ".meta"));
            throw ex;
        }
        return id;
    }

    // ------------------------------------------------------------------
    // Descifrado
    // ------------------------------------------------------------------

    public Path descifrarArchivo(String usuario, PrivateKey clavePrivada, String idArchivo, Path carpetaDestino)
            throws GeneralSecurityException, IOException {

        GestorFicheros.MetadatosArchivo meta = GestorFicheros.leerMetadatosArchivo(idArchivo);
        if (meta == null || !meta.usuario().equals(usuario)) {
            throw new IllegalArgumentException("El usuario no tiene acceso a ese archivo");
        }

        // 1. Se recupera K con la clave privada
        byte[] k = CifradoRSA.descifrarClaveAES(meta.claveCifradaRSA(), clavePrivada);

        // 2. Se descifra el archivo con K
        Files.createDirectories(carpetaDestino);
        Path destino = rutaLibre(carpetaDestino, meta.nombreOriginal());
        try (InputStream inCifrado = GestorFicheros.obtenerFlujoEntradaCifrado(idArchivo);
             OutputStream outClaro = Files.newOutputStream(destino)) {
            CifradorAES.descifrarFlujo(inCifrado, outClaro, k);
        }
        return destino;
    }

    // ------------------------------------------------------------------
    // Consultas
    // ------------------------------------------------------------------

    /** Archivos cifrados que pertenecen al usuario. */
    public List<DetalleArchivo> listarDetalle(String usuario) throws IOException {
        List<DetalleArchivo> resultado = new ArrayList<>();
        for (String id : GestorFicheros.listarIdsArchivos()) {
            GestorFicheros.MetadatosArchivo meta = GestorFicheros.leerMetadatosArchivo(id);
            if (meta != null && meta.usuario().equals(usuario)) {
                resultado.add(new DetalleArchivo(id, meta.nombreOriginal()));
            }
        }
        return resultado;
    }

    // ------------------------------------------------------------------
    // Auxiliares
    // ------------------------------------------------------------------

    /** El nombre se usa para construir rutas de ficheros: se valida para que no pueda salirse de datos/. */
    private void comprobarUsuarioExiste(String usuario) throws IOException {
        if (!NOMBRE_VALIDO.matcher(usuario).matches() || !GestorFicheros.existeUsuario(usuario)) {
            throw new IllegalArgumentException("El usuario '" + usuario + "' no existe");
        }
    }

    /** Si ya existe un archivo con ese nombre, añade (1), (2)... para no sobrescribirlo. */
    private static Path rutaLibre(Path carpeta, String nombreOriginal) {
        String nombre = Path.of(nombreOriginal).getFileName().toString();
        Path destino = carpeta.resolve(nombre);
        int n = 1;
        while (Files.exists(destino)) {
            int punto = nombre.lastIndexOf('.');
            String base = punto > 0 ? nombre.substring(0, punto) : nombre;
            String ext  = punto > 0 ? nombre.substring(punto) : "";
            destino = carpeta.resolve(base + " (" + n++ + ")" + ext);
        }
        return destino;
    }
}