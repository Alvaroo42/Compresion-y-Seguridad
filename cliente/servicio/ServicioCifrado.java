package cliente.servicio;

import cliente.almacenamiento.AlmacenClaves;
import cliente.almacenamiento.EntradaClave;
import cliente.almacenamiento.GestorFicheros;
import cliente.criptografia.CifradoRSA;
import cliente.criptografia.CifradorAES;
import cliente.criptografia.ProtectorClavePrivada;
import cliente.seguridad.DerivadorClaveContrasena;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.regex.Pattern;

/**
 * Orquesta los procesos seguros (todo en local, sin servidor). Es la clase que usa la interfaz.
 *
 *  Alta:      (PU, PR) <- RSA-2048;  PR* <- proteger(PR, contraseña)
 *  Sesión:    PR <- recuperar(PR*, contraseña)
 *  Cifrar:    K <- aleatoria;  C <- IV || E_AES(K, M);  K* <- E_RSA(PU, K)
 *  Descifrar: K <- D_RSA(PR, K*);  M <- D_AES(K, C)
 *
 * Opcionalmente, setRegistro(...) recibe una línea de texto por cada paso criptográfico
 * (la interfaz la muestra en su panel de registro). Nunca se registran claves en claro.
 */
public class ServicioCifrado {

    private static final Pattern NOMBRE_VALIDO = Pattern.compile("[A-Za-z0-9_.-]{3,32}");
    public static final int LONGITUD_MIN_CONTRASENA = 4;

    /** Un archivo cifrado tal como se muestra en la interfaz. 'tamano' es el del archivo original. */
    public record DetalleArchivo(String id, String nombre, long tamano, Instant fechaCifrado) {
        @Override
        public String toString() {
            return nombre;
        }
    }

    private final AlmacenClaves almacen;
    private Consumer<String> registro = mensaje -> { };

    public ServicioCifrado() {
        this.almacen = new AlmacenClaves();
    }

    /** Recibe una línea de texto por cada paso (para mostrarlo en la interfaz). */
    public void setRegistro(Consumer<String> registro) {
        this.registro = registro == null ? m -> { } : registro;
    }

    // ------------------------------------------------------------------
    // Alta de usuario (genera y guarda su par RSA)
    // ------------------------------------------------------------------

    public void registrarUsuario(String usuario, char[] contrasena) throws GeneralSecurityException, IOException {
        if (!NOMBRE_VALIDO.matcher(usuario).matches()) {
            throw new IllegalArgumentException("Nombre de usuario no válido (3-32 caracteres: letras, números, _ . -)");
        }
        if (contrasena.length < LONGITUD_MIN_CONTRASENA) {
            throw new IllegalArgumentException("La contraseña debe tener al menos " + LONGITUD_MIN_CONTRASENA + " caracteres");
        }
        if (GestorFicheros.existeUsuario(usuario)) {
            throw new IllegalArgumentException("El usuario '" + usuario + "' ya existe");
        }

        log("ALTA de '" + usuario + "'");
        KeyPair par = CifradoRSA.generarParClaves();
        log("  (PU, PR) <- RSA-2048 generado");
        byte[] privadaProtegida = ProtectorClavePrivada.proteger(par.getPrivate(), contrasena);
        log("  salt <- aleatorio (128 bits): "
                + b64Corto(Arrays.copyOf(privadaProtegida, DerivadorClaveContrasena.TAM_SALT)));
        log("  H = SHA3-256(salt || contraseña)  ->  K_AES = H[0..127]");
        log("  PR* = salt || IV || E_AES-CTR(K_AES, PR)   (" + privadaProtegida.length + " B)");
        GestorFicheros.guardarClavesUsuario(usuario, par.getPublic().getEncoded(), privadaProtegida);
        log("  guardado: " + usuario + "_publica.key (PU en claro) y " + usuario + "_privada.cif (PR*)   [OK]");
    }

    /** Comprueba la contraseña intentando descifrar la clave privada. */
    public boolean comprobarContrasena(String usuario, char[] contrasena) throws IOException, GeneralSecurityException {
        try {
            obtenerClavePrivada(usuario, contrasena);
            return true;
        } catch (ProtectorClavePrivada.ContrasenaIncorrectaException e) {
            return false;
        }
    }

    /**
     * Inicia sesión: recupera la clave privada con la contraseña.
     * Lanza ContrasenaIncorrectaException si no es correcta.
     */
    public PrivateKey iniciarSesion(String usuario, char[] contrasena) throws IOException, GeneralSecurityException {
        comprobarUsuarioExiste(usuario);
        log("INICIO DE SESIÓN de '" + usuario + "'");
        byte[] prCifrada = GestorFicheros.leerClavePrivadaCifrada(usuario);
        log("  leída PR* de " + usuario + "_privada.cif   salt = "
                + b64Corto(Arrays.copyOf(prCifrada, DerivadorClaveContrasena.TAM_SALT)));
        log("  H = SHA3-256(salt || contraseña)  ->  K_AES = H[0..127]");
        PrivateKey pr = ProtectorClavePrivada.recuperar(prCifrada, contrasena);
        log("  PR = D_AES-CTR(K_AES, PR*)   [clave privada recuperada en memoria]");
        return pr;
    }

    // ------------------------------------------------------------------
    // Cifrado de un archivo multimedia
    // ------------------------------------------------------------------

    /** Cifra el archivo con una clave AES nueva y devuelve el id asignado. */
    public String cifrarArchivo(String usuario, Path archivo) throws GeneralSecurityException, IOException {
        comprobarUsuarioExiste(usuario);
        if (!Files.isRegularFile(archivo)) {
            throw new IllegalArgumentException("No existe el archivo: " + archivo);
        }

        log("CIFRAR '" + archivo.getFileName() + "' (" + tamano(Files.size(archivo)) + ")");
        PublicKey pu = CifradoRSA.cargarClavePublica(GestorFicheros.leerClavePublica(usuario));
        byte[] k = CifradorAES.generarClaveAES();          // clave distinta por archivo
        log("  K <- aleatoria AES-128 (distinta para cada archivo)");
        String id = UUID.randomUUID().toString();
        Path destino = GestorFicheros.rutaArchivoCifrado(id);

        try {
            long t0 = System.currentTimeMillis();
            CifradorAES.cifrarArchivo(archivo, destino, k);            // C = IV || E_AES(K, M)
            log("  C = IV || E_AES-CTR(K, M)   (" + tamano(Files.size(destino)) + ", "
                    + (System.currentTimeMillis() - t0) + " ms)");
            byte[] kCifrada = CifradoRSA.cifrarClaveAES(k, pu);        // K* = E_RSA(PU, K)
            log("  K* = E_RSA-OAEP(PU, K)   (" + kCifrada.length + " B) = " + b64Corto(kCifrada));
            almacen.registrar(new EntradaClave(id, usuario, archivo.getFileName().toString(), kCifrada));
            log("  guardado: " + destino.getFileName() + " y almacen_claves.txt (K* en Base64)   [OK]");
        } catch (GeneralSecurityException | IOException ex) {
            Files.deleteIfExists(destino); // no dejar un .cif huérfano sin clave
            throw ex;
        } finally {
            Arrays.fill(k, (byte) 0);      // borrar la clave en claro de memoria
        }
        return id;
    }

    // ------------------------------------------------------------------
    // Descifrado
    // ------------------------------------------------------------------

    /** Descifra el archivo 'idArchivo' y lo deja en 'carpetaDestino'. Devuelve la ruta creada. */
    public Path descifrarArchivo(String usuario, char[] contrasena, String idArchivo, Path carpetaDestino)
            throws GeneralSecurityException, IOException {
        // Se comprueba el acceso antes de pedir la clave privada
        almacen.buscar(idArchivo, usuario)
                .orElseThrow(() -> new IllegalArgumentException("El usuario no tiene acceso a ese archivo"));
        PrivateKey pr = obtenerClavePrivada(usuario, contrasena);
        return descifrarArchivo(usuario, pr, idArchivo, carpetaDestino);
    }

    /** Igual que el anterior pero con la clave privada ya recuperada (sesión iniciada). */
    public Path descifrarArchivo(String usuario, PrivateKey clavePrivada, String idArchivo, Path carpetaDestino)
            throws GeneralSecurityException, IOException {
        EntradaClave entrada = almacen.buscar(idArchivo, usuario)
                .orElseThrow(() -> new IllegalArgumentException("El usuario no tiene acceso a ese archivo"));

        log("DESCIFRAR '" + entrada.getNombreOriginal() + "'");
        log("  K* leída del almacén de claves   (" + entrada.getClaveCifrada().length + " B) = "
                + b64Corto(entrada.getClaveCifrada()));
        byte[] k = CifradoRSA.descifrarClaveAES(entrada.getClaveCifrada(), clavePrivada);   // K = D_RSA(PR, K*)
        log("  K = D_RSA-OAEP(PR, K*)   (128 bits)");
        try {
            Files.createDirectories(carpetaDestino);
            Path destino = rutaLibre(carpetaDestino, entrada.getNombreOriginal());
            long t0 = System.currentTimeMillis();
            CifradorAES.descifrarArchivo(GestorFicheros.rutaArchivoCifrado(idArchivo), destino, k); // M = D_AES(K, C)
            log("  M = D_AES-CTR(K, C)   (" + (System.currentTimeMillis() - t0) + " ms) -> "
                    + destino.getFileName() + "   [OK]");
            return destino;
        } finally {
            Arrays.fill(k, (byte) 0);
        }
    }

    // ------------------------------------------------------------------
    // Consultas
    // ------------------------------------------------------------------

    public List<EntradaClave> listarArchivos(String usuario) throws IOException {
        return almacen.listarPorUsuario(usuario);
    }

    /** Archivos del usuario con su tamaño original y fecha de cifrado (para la tabla de la interfaz). */
    public List<DetalleArchivo> listarDetalle(String usuario) throws IOException {
        List<DetalleArchivo> resultado = new ArrayList<>();
        for (EntradaClave e : almacen.listarPorUsuario(usuario)) {
            Path cif = GestorFicheros.rutaArchivoCifrado(e.getIdArchivo());
            if (!Files.exists(cif)) continue; // entrada sin archivo (borrado a mano): se ignora
            resultado.add(new DetalleArchivo(
                    e.getIdArchivo(),
                    e.getNombreOriginal(),
                    Math.max(0, Files.size(cif) - CifradorAES.TAM_IV), // el .cif lleva 16 bytes de IV delante
                    Files.getLastModifiedTime(cif).toInstant()));
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

    /** Primeros caracteres en Base64, sólo para mostrar (nunca se usa con claves en claro). */
    private static String b64Corto(byte[] datos) {
        String s = Base64.getEncoder().encodeToString(datos);
        return s.length() > 24 ? s.substring(0, 24) + "…" : s;
    }

    private static String tamano(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024L * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024));
        return String.format("%.2f GB", bytes / (1024.0 * 1024 * 1024));
    }

    /** Evita sobrescribir archivos y rutas del tipo "../../algo" guardadas en el almacén. */
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
