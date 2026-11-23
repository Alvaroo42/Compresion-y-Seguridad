package servidor.almacenamiento;

import comun.Protocolo;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.Comparator;
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

    // Un archivo guardado en la carpeta de un usuario: su id y el contenido de su .meta
    public record ArchivoGuardado(String id, Properties meta) {
    }

    public AlmacenUsuarios(Path directorioDatos) throws IOException {
        this.carpetaUsuarios = Files.createDirectories(directorioDatos.resolve("usuarios")).toAbsolutePath().normalize();
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
