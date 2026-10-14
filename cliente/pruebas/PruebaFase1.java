package cliente.pruebas;

import cliente.almacenamiento.AlmacenClaves;
import cliente.almacenamiento.EntradaClave;
import cliente.almacenamiento.GestorFicheros;
import cliente.criptografia.CifradoRSA;
import cliente.criptografia.ProtectorClavePrivada;
import cliente.seguridad.DerivadorClaveContrasena;
import cliente.seguridad.DerivadorClaveContrasena.ClavesDerivadas;
import cliente.servicio.ServicioCifrado;

import java.util.Arrays;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Prueba automática de toda la Fase 1. Ejecutar antes de cada entrega:
 *   java -cp out cliente.pruebas.PruebaFase1
 */
public class PruebaFase1 {

    private static int ok = 0, fallos = 0;

    public static void main(String[] args) throws Exception {
        Path tmp = Files.createTempDirectory("fase1_prueba");
        GestorFicheros.setDirectorioDatos(tmp.resolve("datos"));
        ServicioCifrado servicio = new ServicioCifrado();

        try {
            // --- Archivos de prueba (imagen, audio, "vídeo" grande) ---
            Path originales = Files.createDirectories(tmp.resolve("originales"));
            Path img = crearArchivo(originales.resolve("foto.jpg"), 300 * 1024);
            Path mp3 = crearArchivo(originales.resolve("canción.mp3"), 4 * 1024 * 1024);
            Path mp4 = crearArchivo(originales.resolve("video.mp4"), 200L * 1024 * 1024);

            // --- 0. Derivación de claves con SHA3-256 ---
            probarDerivador();

            // --- 1. Alta de usuario ---
            char[] pass = "Contraseña-Segura-123".toCharArray();
            servicio.registrarUsuario("alice", pass);
            comprobar("Usuario creado", GestorFicheros.existeUsuario("alice"));
            comprobar("Contraseña correcta verifica", servicio.comprobarContrasena("alice", pass));
            comprobar("Contraseña incorrecta no verifica",
                    !servicio.comprobarContrasena("alice", "otra-cosa-xx".toCharArray()));
            comprobar("Fichero de clave privada no contiene la PKCS#8 en claro",
                    !contiene(GestorFicheros.leerClavePrivadaCifrada("alice"), new byte[]{0x30, (byte) 0x82}, 0));

            // --- 2. Cifrado ---
            Path salida = tmp.resolve("descifrados");
            for (Path original : List.of(img, mp3, mp4)) {
                long t0 = System.nanoTime();
                String id = servicio.cifrarArchivo("alice", original);
                long tCif = (System.nanoTime() - t0) / 1_000_000;
                Path cif = GestorFicheros.rutaArchivoCifrado(id);

                comprobar(original.getFileName() + ": tamaño cifrado = original + 16 (IV)",
                        Files.size(cif) == Files.size(original) + 16);
                comprobar(original.getFileName() + ": cifrado distinto del original",
                        !MessageDigest.isEqual(sha256(cif), sha256(original)));

                t0 = System.nanoTime();
                Path desc = servicio.descifrarArchivo("alice", pass, id, salida);
                long tDes = (System.nanoTime() - t0) / 1_000_000;
                comprobar(original.getFileName() + ": SHA-256 descifrado == original  (cifrar "
                                + tCif + " ms, descifrar " + tDes + " ms)",
                        MessageDigest.isEqual(sha256(desc), sha256(original)));
            }

            // --- 3. Una clave distinta por archivo ---
            servicio.cifrarArchivo("alice", img); // mismo archivo otra vez
            List<EntradaClave> entradas = new AlmacenClaves().listarPorUsuario("alice");
            PrivateKeyHolder pr = new PrivateKeyHolder(ProtectorClavePrivada.recuperar(
                    GestorFicheros.leerClavePrivadaCifrada("alice"), pass));
            Set<String> claves = new HashSet<>();
            for (EntradaClave e : entradas) {
                byte[] k = CifradoRSA.descifrarClaveAES(e.getClaveCifrada(), pr.clave);
                comprobar("Clave de " + e.getNombreOriginal() + " es AES-128", k.length == 16);
                claves.add(java.util.HexFormat.of().formatHex(k));
            }
            comprobar("Todas las claves AES son distintas (" + entradas.size() + " archivos)",
                    claves.size() == entradas.size());

            // --- 4. El almacén no contiene claves AES en claro ---
            String almacen = Files.readString(GestorFicheros.getDirectorioDatos().resolve("almacen_claves.txt"),
                    StandardCharsets.UTF_8);
            boolean fuga = false;
            for (String hex : claves) {
                if (almacen.toLowerCase().contains(hex)) fuga = true;
                byte[] k = java.util.HexFormat.of().parseHex(hex);
                if (almacen.contains(java.util.Base64.getEncoder().encodeToString(k))) fuga = true;
            }
            comprobar("El almacén no contiene ninguna clave AES en claro", !fuga);

            // --- 5. Contraseña incorrecta al descifrar ---
            try {
                servicio.descifrarArchivo("alice", "incorrecta!!".toCharArray(), entradas.get(0).getIdArchivo(), salida);
                comprobar("Descifrar con contraseña incorrecta falla", false);
            } catch (ProtectorClavePrivada.ContrasenaIncorrectaException e) {
                comprobar("Descifrar con contraseña incorrecta falla", true);
            }

            // --- 6. Otro usuario no puede descifrar los archivos de alice ---
            servicio.registrarUsuario("bob", "clave-de-bob-99".toCharArray());
            try {
                servicio.descifrarArchivo("bob", "clave-de-bob-99".toCharArray(), entradas.get(0).getIdArchivo(), salida);
                comprobar("bob no puede descifrar archivos de alice", false);
            } catch (IllegalArgumentException e) {
                comprobar("bob no puede descifrar archivos de alice", true);
            }

            // --- 7. Validaciones de alta ---
            comprobarLanza("Usuario duplicado rechazado", () -> servicio.registrarUsuario("alice", "12345678".toCharArray()));
            comprobarLanza("Contraseña corta rechazada", () -> servicio.registrarUsuario("carol", "123".toCharArray()));
            comprobarLanza("Nombre con ../ rechazado", () -> servicio.registrarUsuario("../x", "12345678".toCharArray()));

        } finally {
            borrar(tmp);
        }

        System.out.println();
        System.out.println("Resultado: " + ok + " OK, " + fallos + " fallos");
        if (fallos > 0) System.exit(1);
    }

    // ------------------------------------------------------------------

    /** Comprueba el módulo cliente.seguridad contra valores calculados con otra implementación (Python hashlib). */
    private static void probarDerivador() throws Exception {
        java.util.HexFormat hex = java.util.HexFormat.of();

        // Vector 1: salt = 16 ceros, contraseña "1234"
        byte[] h1 = DerivadorClaveContrasena.hash("1234".toCharArray(), new byte[16]);
        comprobar("SHA3-256(salt0 || \"1234\") coincide con el valor de referencia",
                hex.formatHex(h1).equals("44fb33de268ae8fbd0b3da690075c7935f67cdcab16ed92e6b5f3cd5c0e0fa84"));

        // Vector 2: salt = 00 01 .. 0f, contraseña con ñ (comprueba UTF-8)
        byte[] salt2 = new byte[16];
        for (int i = 0; i < 16; i++) salt2[i] = (byte) i;
        byte[] h2 = DerivadorClaveContrasena.hash("Contraseña".toCharArray(), salt2);
        comprobar("SHA3-256 con 'ñ' usa UTF-8 (coincide con referencia)",
                hex.formatHex(h2).equals("5d6b15643002d7c2f66c6bf350b42eebd76071e16d1cda0d81dd49c82b310349"));

        // Las dos mitades
        try (ClavesDerivadas c = DerivadorClaveContrasena.derivar("1234".toCharArray(), new byte[16])) {
            comprobar("K_AES = primeros 128 bits del hash",
                    hex.formatHex(c.getClaveAES()).equals("44fb33de268ae8fbd0b3da690075c793"));
            comprobar("Token servidor = últimos 128 bits del hash",
                    hex.formatHex(c.getTokenServidor()).equals("5f67cdcab16ed92e6b5f3cd5c0e0fa84"));
        }

        // Determinista con mismo salt, distinto con otro salt o contraseña
        byte[] s = DerivadorClaveContrasena.generarSalt();
        byte[] a = DerivadorClaveContrasena.hash("1234".toCharArray(), s);
        byte[] b = DerivadorClaveContrasena.hash("1234".toCharArray(), s);
        byte[] otroSalt = DerivadorClaveContrasena.hash("1234".toCharArray(), DerivadorClaveContrasena.generarSalt());
        byte[] otraPass = DerivadorClaveContrasena.hash("1235".toCharArray(), s);
        comprobar("Misma contraseña + mismo salt -> mismo hash", MessageDigest.isEqual(a, b));
        comprobar("Misma contraseña + otro salt -> hash distinto", !MessageDigest.isEqual(a, otroSalt));
        comprobar("'1234' vs '1235' -> hash distinto", !MessageDigest.isEqual(a, otraPass));

        // close() borra las claves
        ClavesDerivadas c = DerivadorClaveContrasena.derivar("1234".toCharArray(), s);
        c.close();
        comprobar("close() borra K_AES de memoria", Arrays.equals(c.getClaveAES(), new byte[16]));

        comprobarLanza("Contraseña vacía rechazada",
                () -> DerivadorClaveContrasena.hash(new char[0], s));
        comprobarLanza("Salt de tamaño incorrecto rechazado",
                () -> DerivadorClaveContrasena.hash("1234".toCharArray(), new byte[8]));
    }

    private static class PrivateKeyHolder {
        final java.security.PrivateKey clave;
        PrivateKeyHolder(java.security.PrivateKey c) { clave = c; }
    }

    interface Accion { void ejecutar() throws Exception; }

    private static void comprobarLanza(String desc, Accion a) {
        try {
            a.ejecutar();
            comprobar(desc, false);
        } catch (IllegalArgumentException e) {
            comprobar(desc, true);
        } catch (Exception e) {
            comprobar(desc + " (excepción inesperada " + e + ")", false);
        }
    }

    private static void comprobar(String desc, boolean condicion) {
        System.out.println((condicion ? "[OK]    " : "[FALLO] ") + desc);
        if (condicion) ok++; else fallos++;
    }

    private static Path crearArchivo(Path ruta, long tam) throws Exception {
        Random r = new Random(42);
        byte[] buf = new byte[1024 * 1024];
        try (OutputStream out = Files.newOutputStream(ruta)) {
            long restante = tam;
            while (restante > 0) {
                r.nextBytes(buf);
                int n = (int) Math.min(buf.length, restante);
                out.write(buf, 0, n);
                restante -= n;
            }
        }
        return ruta;
    }

    private static byte[] sha256(Path p) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (var in = Files.newInputStream(p)) {
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) != -1) md.update(buf, 0, n);
        }
        return md.digest();
    }

    private static boolean contiene(byte[] datos, byte[] patron, int desde) {
        // La PKCS#8 de RSA-2048 empieza por 30 82: comprobamos que no aparece tras la cabecera salt||n||IV
        int inicio = ProtectorClavePrivada.TAM_CABECERA;
        return datos.length > inicio + 1 && datos[inicio] == patron[0] && datos[inicio + 1] == patron[1];
    }

    private static void borrar(Path dir) throws Exception {
        try (Stream<Path> s = Files.walk(dir)) {
            s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }
}
