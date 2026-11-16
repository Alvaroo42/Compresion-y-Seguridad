package servidor.almacenamiento;

import comun.Protocolo;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileTime;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.stream.Stream;

/**
 * Almacén del servidor: una carpeta por usuario. El servidor no cifra ni descifra nada; solo guarda y
 * devuelve bytes que ya llegan cifrados del cliente.
 *
 *   servidor_datos/usuarios/<usuario>/perfil.properties   hash de la clave de login, salt, parámetros, pública, privada cifrada
 *   servidor_datos/usuarios/<usuario>/archivos/<id>.cif   IV ‖ contenido cifrado (Base64, como en la fase 1)
 *   servidor_datos/usuarios/<usuario>/archivos/<id>.meta  nombre, clave AES cifrada (RSA), emisor
 */
public class AlmacenUsuarios {

    private static final String PERFIL = "perfil.properties";
    private static final String ARCHIVOS = "archivos";

    private final Path carpetaUsuarios;
    private final Path carpetaGoogle;

    // Un archivo guardado en la carpeta de un usuario: su id y el contenido de su .meta
    public record ArchivoGuardado(String id, Properties meta) {
    }

    public AlmacenUsuarios(Path directorioDatos) throws IOException {
        this.carpetaUsuarios = Files.createDirectories(directorioDatos.resolve("usuarios")).toAbsolutePath().normalize();
        this.carpetaGoogle = Files.createDirectories(directorioDatos.resolve("google")).toAbsolutePath().normalize();
    }

    // ------------------------------------------------------------------ usuarios

    public boolean existe(String usuario) {
        return Protocolo.usuarioValido(usuario) && Files.isRegularFile(carpetaDe(usuario).resolve(PERFIL));
    }

    // Crea la carpeta del usuario y su perfil. createDirectory es atómico: si dos registros llegan a la vez
    // con el mismo nombre, solo uno lo consigue y el otro recibe FileAlreadyExistsException.
    public void crear(String usuario, Map<String, String> perfil) throws IOException {
        Path carpeta = carpetaDe(usuario);
        Files.createDirectory(carpeta);
        try {
            Files.createDirectory(carpeta.resolve(ARCHIVOS));
            escribirAtomico(carpeta.resolve(PERFIL), Protocolo.escribir(perfil));
        } catch (IOException e) {
            borrar(usuario);
            throw e;
        }
    }

    public Properties leerPerfil(String usuario) throws IOException {
        if (!existe(usuario)) {
            return null;
        }
        return Protocolo.leer(Files.readString(carpetaDe(usuario).resolve(PERFIL), StandardCharsets.UTF_8));
    }

    // Borra un usuario a medio crear (solo se usa para deshacer un registro que ha fallado)
    public void borrar(String usuario) throws IOException {
        Path carpeta = carpetaDe(usuario);
        if (!Files.exists(carpeta)) {
            return;
        }
        try (Stream<Path> rutas = Files.walk(carpeta)) {
            for (Path ruta : rutas.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(ruta);
            }
        }
    }

    // ------------------------------------------------------------------ archivos

    // Fichero temporal donde se va escribiendo una subida (en la misma carpeta, para poder moverlo de forma atómica)
    public Path nuevoTemporal(String usuario) throws IOException {
        return Files.createTempFile(carpetaArchivos(usuario), ".subida-", ".tmp");
    }

    // Guarda el .cif recibido y su .meta con un id nuevo (UUID). Primero el .cif y después el .meta: la lista
    // se construye con los .meta, así que nunca aparece un archivo a medio guardar.
    public String guardarArchivo(String propietario, Path temporal, Map<String, String> meta) throws IOException {
        Path carpeta = carpetaArchivos(propietario);
        String id = UUID.randomUUID().toString();
        Path cif = dentroDe(carpeta, id + ".cif");
        Files.move(temporal, cif, StandardCopyOption.ATOMIC_MOVE);
        try {
            escribirAtomico(dentroDe(carpeta, id + ".meta"), Protocolo.escribir(meta));
        } catch (IOException e) {
            Files.deleteIfExists(cif);
            throw e;
        }
        return id;
    }

    // Ruta del .cif de un archivo del usuario, o null si el id no es válido o el archivo no es suyo
    public Path rutaCif(String usuario, String id) {
        if (!Protocolo.idValido(id) || !existe(usuario)) {
            return null;
        }
        Path cif = dentroDe(carpetaArchivos(usuario), id + ".cif");
        Path meta = dentroDe(carpetaArchivos(usuario), id + ".meta");
        return Files.isRegularFile(cif) && Files.isRegularFile(meta) ? cif : null;
    }

    // Archivos del usuario (propios y compartidos con él), del más antiguo al más reciente
    public List<ArchivoGuardado> listar(String usuario) throws IOException {
        List<ArchivoGuardado> archivos = new ArrayList<>();
        if (!existe(usuario)) {
            return archivos;
        }
        Path carpeta = carpetaArchivos(usuario);
        List<Path> metas = new ArrayList<>();
        try (DirectoryStream<Path> lista = Files.newDirectoryStream(carpeta, "*.meta")) {
            lista.forEach(metas::add);
        }
        metas.sort(Comparator.comparing(AlmacenUsuarios::fechaDe));
        for (Path meta : metas) {
            String nombre = meta.getFileName().toString();
            String id = nombre.substring(0, nombre.length() - ".meta".length());
            if (Protocolo.idValido(id)) {
                archivos.add(new ArchivoGuardado(id, Protocolo.leer(Files.readString(meta, StandardCharsets.UTF_8))));
            }
        }
        return archivos;
    }

    // ------------------------------------------------------------------ cuentas de Google (mejora)

    // Une una cuenta de Google con un usuario. Se crea un fichero por cuenta de Google con createFile, que
    // es atómico: una misma cuenta de Google no puede quedar unida a dos usuarios.
    public boolean vincularGoogle(String sub, String usuario) throws IOException {
        try {
            Files.writeString(Files.createFile(rutaGoogle(sub)), usuario, StandardCharsets.UTF_8);
            return true;
        } catch (FileAlreadyExistsException e) {
            return false;
        }
    }

    // Usuario unido a una cuenta de Google, o null si no hay ninguno
    public String usuarioDeGoogle(String sub) throws IOException {
        Path ruta = rutaGoogle(sub);
        return Files.isRegularFile(ruta) ? Files.readString(ruta, StandardCharsets.UTF_8).trim() : null;
    }

    // ------------------------------------------------------------------ rutas seguras

    // Carpeta del usuario. Se valida el nombre y se comprueba que la ruta final queda dentro de usuarios/,
    // así nadie puede escribir fuera de su carpeta con "../".
    private Path carpetaDe(String usuario) {
        if (!Protocolo.usuarioValido(usuario)) {
            throw new IllegalArgumentException("Nombre de usuario no válido");
        }
        return dentroDe(carpetaUsuarios, usuario);
    }

    private Path carpetaArchivos(String usuario) {
        return dentroDe(carpetaDe(usuario), ARCHIVOS);
    }

    // ruta.normalize().startsWith(carpeta): si no se cumple, alguien ha intentado salir de la carpeta
    private static Path dentroDe(Path carpeta, String nombre) {
        Path ruta = carpeta.resolve(nombre).normalize();
        if (!ruta.startsWith(carpeta) || ruta.equals(carpeta)) {
            throw new IllegalArgumentException("Ruta fuera de la carpeta permitida");
        }
        return ruta;
    }

    // El identificador de Google (sub) se guarda resumido con SHA-256 para que el nombre del fichero sea seguro
    private Path rutaGoogle(String sub) {
        try {
            byte[] resumen = MessageDigest.getInstance("SHA-256").digest(sub.getBytes(StandardCharsets.UTF_8));
            return dentroDe(carpetaGoogle, HexFormat.of().formatHex(resumen));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void escribirAtomico(Path destino, String contenido) throws IOException {
        Path temporal = Files.createTempFile(destino.getParent(), ".escribiendo-", ".tmp");
        try {
            Files.writeString(temporal, contenido, StandardCharsets.UTF_8);
            Files.move(temporal, destino, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } finally {
            Files.deleteIfExists(temporal);
        }
    }

    private static FileTime fechaDe(Path ruta) {
        try {
            return Files.getLastModifiedTime(ruta);
        } catch (IOException e) {
            return FileTime.fromMillis(0);
        }
    }
}
