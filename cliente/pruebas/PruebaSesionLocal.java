package cliente.pruebas;

import cliente.almacenamiento.GestorFicheros;
import cliente.criptografia.ProtectorClavePrivada;
import cliente.servicio.ServicioCifrado.DetalleArchivo;
import cliente.servicio.SesionLocal;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Random;
import java.util.stream.Stream;

/**
 * Prueba de la sesión local que usa la interfaz (sin servidor):
 *   java -cp out cliente.pruebas.PruebaSesionLocal
 */
public class PruebaSesionLocal {

    private static int ok = 0, fallos = 0;

    public static void main(String[] args) throws Exception {
        Path tmp = Files.createTempDirectory("prueba_sesion");
        GestorFicheros.setDirectorioDatos(tmp.resolve("datos"));
        try {
            Path img = crearArchivo(tmp.resolve("Fotografía ñ.jpg"), 300 * 1024);
            Path salida = tmp.resolve("descifrados");
            char[] pass = "1234".toCharArray(); // el ejemplo del profesor

            List<String> pasos = new ArrayList<>();
            try (SesionLocal s = new SesionLocal()) {
                s.setRegistro(pasos::add);
                s.registrar("alvaro", pass);
                comprobar("Alta con la contraseña '1234' aceptada", true);
                s.iniciarSesion("alvaro", pass);
                comprobar("Sesión iniciada", "alvaro".equals(s.getUsuario()));

                String id = s.cifrar(img);
                List<DetalleArchivo> lista = s.listar();
                comprobar("Listar devuelve 1 archivo con su nombre original",
                        lista.size() == 1 && lista.get(0).nombre().equals("Fotografía ñ.jpg"));
                comprobar("El tamaño mostrado es el del archivo original (sin los 16 B de IV)",
                        lista.get(0).tamano() == Files.size(img));
                comprobar("Tiene fecha de cifrado", lista.get(0).fechaCifrado() != null);

                Path desc = s.descifrar(id, salida);
                comprobar("Descifrado == original (SHA-256)", MessageDigest.isEqual(sha256(desc), sha256(img)));
                Path desc2 = s.descifrar(id, salida);
                comprobar("Descifrar otra vez no sobrescribe: " + desc2.getFileName(),
                        !desc2.equals(desc) && Files.exists(desc) && Files.exists(desc2));
            }

            comprobar("El registro de pasos recoge alta, sesión, cifrado y descifrado",
                    hay(pasos, "ALTA") && hay(pasos, "INICIO DE SESIÓN") && hay(pasos, "CIFRAR") && hay(pasos, "DESCIFRAR"));
            comprobar("El registro no contiene la contraseña", pasos.stream().noneMatch(p -> p.contains("1234")));

            // Base64 en el almacén
            String almacen = Files.readString(GestorFicheros.getDirectorioDatos().resolve("almacen_claves.txt"),
                    StandardCharsets.UTF_8);
            String[] c = almacen.lines().filter(l -> !l.startsWith("#")).findFirst().orElse("").split(";");
            comprobar("almacen_claves.txt: K* en Base64 (256 bytes = RSA-2048)",
                    c.length == 4 && Base64.getDecoder().decode(c[3]).length == 256);

            // Errores
            try (SesionLocal s = new SesionLocal()) {
                s.iniciarSesion("alvaro", "12345".toCharArray());
                comprobar("Contraseña incorrecta rechazada", false);
            } catch (ProtectorClavePrivada.ContrasenaIncorrectaException e) {
                comprobar("Contraseña incorrecta rechazada", true);
            }
            try (SesionLocal s = new SesionLocal()) {
                s.iniciarSesion("nadie", pass);
                comprobar("Usuario inexistente rechazado", false);
            } catch (IllegalArgumentException e) {
                comprobar("Usuario inexistente rechazado (" + e.getMessage() + ")", true);
            }
            try (SesionLocal s = new SesionLocal()) {
                s.registrar("alvaro", pass);
                comprobar("Usuario duplicado rechazado", false);
            } catch (IllegalArgumentException e) {
                comprobar("Usuario duplicado rechazado", true);
            }
            try (SesionLocal s = new SesionLocal()) {
                s.cifrar(img);
                comprobar("Cifrar sin iniciar sesión rechazado", false);
            } catch (IllegalStateException e) {
                comprobar("Cifrar sin iniciar sesión rechazado", true);
            }
            try (SesionLocal s = new SesionLocal()) {
                s.registrar("ana", "123".toCharArray());
                comprobar("Contraseña de 3 caracteres rechazada", false);
            } catch (IllegalArgumentException e) {
                comprobar("Contraseña de 3 caracteres rechazada", true);
            }
        } finally {
            borrar(tmp);
        }

        System.out.println();
        System.out.println("Resultado: " + ok + " OK, " + fallos + " fallos");
        if (fallos > 0) System.exit(1);
    }

    private static boolean hay(List<String> pasos, String inicio) {
        return pasos.stream().anyMatch(p -> p.startsWith(inicio));
    }

    private static void comprobar(String desc, boolean condicion) {
        System.out.println((condicion ? "[OK]    " : "[FALLO] ") + desc);
        if (condicion) ok++; else fallos++;
    }

    private static Path crearArchivo(Path ruta, long tam) throws Exception {
        byte[] datos = new byte[(int) tam];
        new Random(3).nextBytes(datos);
        try (OutputStream out = Files.newOutputStream(ruta)) {
            out.write(datos);
        }
        return ruta;
    }

    private static byte[] sha256(Path p) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(p));
    }

    private static void borrar(Path dir) throws Exception {
        try (Stream<Path> s = Files.walk(dir)) {
            s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }
}
