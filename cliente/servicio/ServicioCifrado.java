package cliente.servicio;

import cliente.almacenamiento.GestorFicheros;
import cliente.criptografia.CifradoRSA;
import cliente.criptografia.CifradorAES;
import cliente.criptografia.ProtectorClavePrivada;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.regex.Pattern;

public class ServicioCifrado {

    private static final Pattern NOMBRE_VALIDO = Pattern.compile("[A-Za-z0-9_.-]{3,32}");
    public static final int LONGITUD_MIN_CONTRASENA = 4;

    public record DetalleArchivo(String id, String nombre, long tamano, Instant fechaCifrado) {
        @Override
        public String toString() {
            return nombre;
        }
    }

    private Consumer<String> registro = mensaje -> { };

    public ServicioCifrado() {}

    public void setRegistro(Consumer<String> registro) {
        this.registro = registro == null ? m -> { } : registro;
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

        log("ALTA de '" + usuario + "'");
        KeyPair par = CifradoRSA.generarParClaves();
        byte[] privadaProtegida = ProtectorClavePrivada.proteger(par.getPrivate(), contrasena);
        GestorFicheros.guardarClavesUsuario(usuario, par.getPublic().getEncoded(), privadaProtegida);
        log("  guardado: claves pública y privada del usuario   [OK]");
    }

    public boolean comprobarContrasena(String usuario, char[] contrasena) throws IOException, GeneralSecurityException {
        try {
            obtenerClavePrivada(usuario, contrasena);
            return true;
        } catch (ProtectorClavePrivada.ContrasenaIncorrectaException e) {
            return false;
        }
    }

    public PrivateKey iniciarSesion(String usuario, char[] contrasena) throws IOException, GeneralSecurityException {
        comprobarUsuarioExiste(usuario);
        log("INICIO DE SESIÓN de '" + usuario + "'");
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

        log("CIFRAR '" + archivo.getFileName() + "'");
        PublicKey pu = CifradoRSA.cargarClavePublica(GestorFicheros.leerClavePublica(usuario));
        byte[] k = CifradorAES.generarClaveAES();
        String id = UUID.randomUUID().toString();
        
        // Ya no declaramos 'Path destino' aquí para el archivo .cif.
        // Solo necesitamos el ID para pedirle el flujo a GestorFicheros.

        try {
            // 1. Abrimos el archivo original para leer
            try (java.io.InputStream in = Files.newInputStream(archivo);
                 // 2. Pedimos a GestorFicheros el flujo de salida ya preparado con Base64
                 java.io.OutputStream outCifrado = GestorFicheros.obtenerFlujoSalidaCifrado(id)) {
                
                // 3. CifradorAES procesa el flujo (sin saber que acaba en un archivo Base64)
                CifradorAES.cifrarFlujo(in, outCifrado, k);
            }

            byte[] kCifrada = CifradoRSA.cifrarClaveAES(k, pu);
            GestorFicheros.guardarMetadatosArchivo(id, usuario, archivo.getFileName().toString(), kCifrada);
            log("  guardado: archivo " + id + ".cif y sus metadatos   [OK]");
            
        } catch (GeneralSecurityException | IOException ex) {
            // Si algo falla, limpiamos los archivos a medias usando GestorFicheros
            Files.deleteIfExists(GestorFicheros.rutaArchivoCifrado(id)); 
            Files.deleteIfExists(GestorFicheros.directorioCifrados().resolve(id + ".meta"));
            throw ex;
        } finally {
            java.util.Arrays.fill(k, (byte) 0);
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

        log("DESCIFRAR '" + meta.nombreOriginal() + "'");
        byte[] k = CifradoRSA.descifrarClaveAES(meta.claveCifradaRSA(), clavePrivada); 
        
        try {
            Files.createDirectories(carpetaDestino);
            Path destino = rutaLibre(carpetaDestino, meta.nombreOriginal());
            
            // 1. Pedimos a GestorFicheros el flujo de entrada (ya decodificando Base64)
            try (java.io.InputStream inCifrado = GestorFicheros.obtenerFlujoEntradaCifrado(idArchivo);
                 // 2. Abrimos el archivo final donde quedará en claro
                 java.io.OutputStream outClaro = Files.newOutputStream(destino)) {
                
                // 3. CifradorAES hace su trabajo sobre los flujos
                CifradorAES.descifrarFlujo(inCifrado, outClaro, k);
            }
            
            log("  Archivo descifrado correctamente   [OK]");
            return destino;
        } finally {
            java.util.Arrays.fill(k, (byte) 0);
        }
    }

    // ------------------------------------------------------------------
    // Consultas
    // ------------------------------------------------------------------

    public List<DetalleArchivo> listarDetalle(String usuario) throws IOException {
        List<DetalleArchivo> resultado = new ArrayList<>();
        for (String id : GestorFicheros.listarIdsArchivos()) {
            GestorFicheros.MetadatosArchivo meta = GestorFicheros.leerMetadatosArchivo(id);
            
            if (meta != null && meta.usuario().equals(usuario)) {
                Path cif = GestorFicheros.rutaArchivoCifrado(id);
                if (!Files.exists(cif)) continue; 
                
                resultado.add(new DetalleArchivo(
                        id,
                        meta.nombreOriginal(),
                        Math.max(0, Files.size(cif) - CifradorAES.TAM_IV), 
                        Files.getLastModifiedTime(cif).toInstant()));
            }
        }
        return resultado;
    }

    // ------------------------------------------------------------------
    // Auxiliares
    // ------------------------------------------------------------------

    private PrivateKey obtenerClavePrivada(String usuario, char[] contrasena) throws IOException, GeneralSecurityException {
        comprobarUsuarioExiste(usuario);
        return ProtectorClavePrivada.recuperar(GestorFicheros.leerClavePrivadaCifrada(usuario), contrasena);
    }

    private void comprobarUsuarioExiste(String usuario) throws IOException {
        if (!NOMBRE_VALIDO.matcher(usuario).matches() || !GestorFicheros.existeUsuario(usuario)) {
            throw new IllegalArgumentException("El usuario '" + usuario + "' no existe");
        }
    }

    private void log(String mensaje) {
        registro.accept(mensaje);
    }

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