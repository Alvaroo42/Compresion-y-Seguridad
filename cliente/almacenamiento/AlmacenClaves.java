package cliente.almacenamiento;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * Almacén de claves AES en un fichero de texto (datos/almacen_claves.txt).
 *
 * Cada línea:  idArchivo;usuario;Base64(nombreOriginal);Base64(E_RSA(PU_usuario, K_archivo))
 *
 * Ninguna clave AES se guarda en claro: sólo su versión cifrada con RSA.
 * El nombre original va en Base64 para que pueda contener ';' o caracteres raros.
 */
public class AlmacenClaves {

    private static final String SEPARADOR = ";";
    private static final String CABECERA =
            "# idArchivo;usuario;nombreOriginal(Base64);claveAES_cifrada_RSA(Base64)";

    private final Path fichero;

    public AlmacenClaves() {
        this(GestorFicheros.getDirectorioDatos().resolve("almacen_claves.txt"));
    }

    public AlmacenClaves(Path fichero) {
        this.fichero = fichero;
    }

    /** Añade una entrada al final del fichero. */
    public synchronized void registrar(EntradaClave e) throws IOException {
        Files.createDirectories(fichero.toAbsolutePath().getParent());
        if (!Files.exists(fichero)) {
            Files.writeString(fichero, CABECERA + System.lineSeparator(), StandardCharsets.UTF_8);
        }
        String linea = String.join(SEPARADOR,
                e.getIdArchivo(),
                e.getUsuario(),
                b64(e.getNombreOriginal().getBytes(StandardCharsets.UTF_8)),
                b64(e.getClaveCifrada()));
        Files.writeString(fichero, linea + System.lineSeparator(), StandardCharsets.UTF_8,
                StandardOpenOption.APPEND);
    }

    /** Busca la clave de un archivo para un usuario concreto. */
    public synchronized Optional<EntradaClave> buscar(String idArchivo, String usuario) throws IOException {
        for (EntradaClave e : leerTodas()) {
            if (e.getIdArchivo().equals(idArchivo) && e.getUsuario().equals(usuario)) {
                return Optional.of(e);
            }
        }
        return Optional.empty();
    }

    /** Todos los archivos a los que tiene acceso un usuario. */
    public synchronized List<EntradaClave> listarPorUsuario(String usuario) throws IOException {
        List<EntradaClave> resultado = new ArrayList<>();
        for (EntradaClave e : leerTodas()) {
            if (e.getUsuario().equals(usuario)) resultado.add(e);
        }
        return resultado;
    }

    public synchronized List<EntradaClave> leerTodas() throws IOException {
        List<EntradaClave> entradas = new ArrayList<>();
        if (!Files.exists(fichero)) return entradas;

        for (String linea : Files.readAllLines(fichero, StandardCharsets.UTF_8)) {
            if (linea.isBlank() || linea.startsWith("#")) continue;
            String[] c = linea.split(SEPARADOR, -1);
            if (c.length != 4) continue; // línea mal formada: se ignora
            entradas.add(new EntradaClave(
                    c[0],
                    c[1],
                    new String(Base64.getDecoder().decode(c[2]), StandardCharsets.UTF_8),
                    Base64.getDecoder().decode(c[3])));
        }
        return entradas;
    }

    private static String b64(byte[] datos) {
        return Base64.getEncoder().encodeToString(datos);
    }
}
