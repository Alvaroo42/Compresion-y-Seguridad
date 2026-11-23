package cliente.servicio;

import cliente.codificacion.Codificador;
import cliente.criptografia.CifradoRSA;
import cliente.criptografia.CifradorAES;
import cliente.criptografia.FirmaDigital;
import cliente.criptografia.FirmaDigital.FirmaNoValidaException;
import cliente.criptografia.ProtectorClavePrivada;
import cliente.red.ClienteServidor;
import cliente.red.ClienteServidor.ArchivoRemoto;
import cliente.red.ClienteServidor.RespuestaLogin;
import cliente.seguridad.DerivadorClaveContrasena;
import cliente.seguridad.DerivadorClaveContrasena.ClavesDerivadas;
import comun.Protocolo;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * Toda la lógica y todo el cifrado están aquí, en el cliente. Es el mismo flujo de la fase 1, pero donde antes
 * se leía o escribía en datos/ ahora se llama al servidor (ClienteServidor). Al servidor solo llegan datos
 * cifrados; la contraseña y la clave de datos nunca salen de este equipo.
 */
public class ServicioCifrado {

    // Un archivo de la lista (la interfaz muestra su nombre original y, si es compartido, quién lo envió)
    public record DetalleArchivo(String id, String nombre, String emisor, boolean propio,
                                 byte[] claveAESCifrada, String nombreCifrado, byte[] firma) {
        @Override
        public String toString() {
            return propio ? nombre : nombre + "     (compartido por " + emisor + ")";
        }
    }

    // Lo que queda en memoria tras iniciar sesión
    public record DatosSesion(String token, Instant caducidad, PrivateKey clavePrivada, PublicKey clavePublica,
                              List<DetalleArchivo> archivos) {
    }

    private final ClienteServidor red;
    private final Codificador codificador = new Codificador();

    public ServicioCifrado(ClienteServidor red) {
        this.red = red;
    }

    // 7.1 Registro: validar, derivar las dos claves, generar RSA-2048, cifrar la privada con la clave de datos
    // y mandar al servidor usuario, clave de login, pública y privada cifrada.
    public void registrarUsuario(String usuario, char[] contrasena) throws GeneralSecurityException, IOException {
        if (!Protocolo.usuarioValido(usuario)) {
            throw new IllegalArgumentException("Nombre de usuario no válido: de 3 a 32 letras, números, _ . o -");
        }
        if (contrasena.length < Protocolo.LONGITUD_MIN_CONTRASENA) {
            throw new IllegalArgumentException("La contraseña debe tener al menos " + Protocolo.LONGITUD_MIN_CONTRASENA + " caracteres");
        }
        ClavesDerivadas claves = DerivadorClaveContrasena.derivar(contrasena, DerivadorClaveContrasena.saltDe(usuario));
        try {
            KeyPair par = CifradoRSA.generarParClaves();
            byte[] privadaCifrada = ProtectorClavePrivada.proteger(par.getPrivate(), claves.datos());
            red.registrar(usuario, claves.login(), par.getPublic().getEncoded(), privadaCifrada);
        } finally {
            claves.borrar();
        }
    }

    // 7.2 Login: derivar de nuevo las dos claves, mandar la de login y, con la respuesta, descifrar la privada
    // con la de datos y preparar la lista de archivos.
    public DatosSesion iniciarSesion(String usuario, char[] contrasena) throws GeneralSecurityException, IOException {
        if (!Protocolo.usuarioValido(usuario)) {
            throw new ClienteServidor.ErrorServidor(401, "Usuario o clave incorrectos");
        }
        ClavesDerivadas claves = DerivadorClaveContrasena.derivar(contrasena, DerivadorClaveContrasena.saltDe(usuario));
        try {
            RespuestaLogin respuesta = red.login(usuario, claves.login());
            PrivateKey privada = ProtectorClavePrivada.recuperar(respuesta.clavePrivadaCifrada(), claves.datos());
            PublicKey publica = CifradoRSA.cargarClavePublica(respuesta.clavePublica());
            comprobarPareja(privada, publica);

            List<DetalleArchivo> archivos = new ArrayList<>();
            for (ArchivoRemoto remoto : respuesta.archivos()) {
                archivos.add(detalle(remoto, usuario, privada));
            }
            // Se da por caducada un poco antes que en el servidor (un 10 %, como mucho 5 s) para no empezar una subida a punto de caducar
            long validez = respuesta.validezSegundos();
            Instant caducidad = Instant.now().plusSeconds(validez - Math.min(5, validez / 10));
            return new DatosSesion(respuesta.token(), caducidad, privada, publica, archivos);
        } finally {
            claves.borrar();
        }
    }

    // 7.3 Cifrar y subir: clave AES K nueva, cifrar el archivo (AES-CTR, por bloques) a un temporal en Base64,
    // cifrar K con la propia clave pública, cifrar también el nombre con K, firmar y subir.
    public DetalleArchivo cifrarYSubir(String token, String usuario, PrivateKey privada, PublicKey publica, Path archivo)
            throws GeneralSecurityException, IOException {
        if (!Files.isRegularFile(archivo)) {
            throw new IllegalArgumentException("No existe el archivo: " + archivo);
        }
        String nombre = archivo.getFileName().toString();
        byte[] k = CifradorAES.generarClaveAES();
        Path temporal = Files.createTempFile("cys-", ".cif");
        try {
            try (InputStream in = Files.newInputStream(archivo);
                 OutputStream out = codificador.envolverSalida(Files.newOutputStream(temporal))) {
                CifradorAES.cifrarFlujo(in, out, k);
            }
            byte[] kCifrada = CifradoRSA.cifrarClaveAES(k, publica);
            String nombreCifrado = cifrarNombre(nombre, k);
            byte[] firma = FirmaDigital.firmar(privada, kCifrada, nombreCifrado, temporal);
            String id = red.subir(token, temporal, nombreCifrado, kCifrada, firma, null);
            return new DetalleArchivo(id, nombre, usuario, true, kCifrada, nombreCifrado, firma);
        } finally {
            Arrays.fill(k, (byte) 0);
            Files.deleteIfExists(temporal);
        }
    }

    // 7.4 Bajar, comprobar la firma, descifrar y guardar en la carpeta elegida (sin sobrescribir nada)
    public Path descifrarArchivo(String token, String usuario, PrivateKey privada, PublicKey publica,
                                 DetalleArchivo archivo, Path carpetaDestino) throws GeneralSecurityException, IOException {
        Path temporal = Files.createTempFile("cys-", ".cif");
        byte[] k = null;
        try {
            red.bajar(token, archivo.id(), temporal);
            comprobarFirma(token, usuario, publica, archivo, temporal);
            k = CifradoRSA.descifrarClaveAES(archivo.claveAESCifrada(), privada);

            Files.createDirectories(carpetaDestino);
            Path destino = rutaLibre(carpetaDestino, archivo.nombre());
            try (InputStream in = codificador.envolverEntrada(Files.newInputStream(temporal));
                 OutputStream out = Files.newOutputStream(destino)) {
                CifradorAES.descifrarFlujo(in, out, k);
            } catch (GeneralSecurityException | IOException e) {
                Files.deleteIfExists(destino);
                throw e;
            }
            return destino;
        } finally {
            if (k != null) {
                Arrays.fill(k, (byte) 0);
            }
            Files.deleteIfExists(temporal);
        }
    }

    // 7.5 Compartir: descifrar K con la propia privada, cifrarla con la pública del destinatario y subir el
    // mismo .cif a la carpeta del destinatario. El archivo no se vuelve a cifrar.
    public void compartirArchivo(String token, String usuario, PrivateKey privada, PublicKey publica,
                                 DetalleArchivo archivo, String destinatario) throws GeneralSecurityException, IOException {
        if (!Protocolo.usuarioValido(destinatario)) {
            throw new IllegalArgumentException("Nombre de usuario no válido: " + destinatario);
        }
        if (destinatario.equals(usuario)) {
            throw new IllegalArgumentException("No puedes compartir un archivo contigo mismo");
        }
        PublicKey publicaDestinatario = CifradoRSA.cargarClavePublica(red.clavePublica(token, destinatario));
        byte[] k = CifradoRSA.descifrarClaveAES(archivo.claveAESCifrada(), privada);
        Path temporal = Files.createTempFile("cys-", ".cif");
        try {
            byte[] kParaDestinatario = CifradoRSA.cifrarClaveAES(k, publicaDestinatario);
            red.bajar(token, archivo.id(), temporal);
            comprobarFirma(token, usuario, publica, archivo, temporal);   // no se reenvía nada manipulado
            byte[] firma = FirmaDigital.firmar(privada, kParaDestinatario, archivo.nombreCifrado(), temporal);
            red.subir(token, temporal, archivo.nombreCifrado(), kParaDestinatario, firma, destinatario);
        } finally {
            Arrays.fill(k, (byte) 0);
            Files.deleteIfExists(temporal);
        }
    }

    // ------------------------------------------------------------------ auxiliares

    // Mejora: la firma se comprueba con la clave pública de quien envió el archivo
    private void comprobarFirma(String token, String usuario, PublicKey publica, DetalleArchivo archivo, Path cif)
            throws GeneralSecurityException, IOException {
        PublicKey publicaEmisor = archivo.emisor().equals(usuario) ? publica
                : CifradoRSA.cargarClavePublica(red.clavePublica(token, archivo.emisor()));
        if (!FirmaDigital.verificar(publicaEmisor, archivo.firma(), archivo.claveAESCifrada(), archivo.nombreCifrado(), cif)) {
            throw new FirmaNoValidaException("El archivo \"" + archivo.nombre() + "\" ha sido modificado o no lo envió " + archivo.emisor()
                    + ": la firma digital no coincide. No se ha descifrado.");
        }
    }

    // Prepara un archivo de la lista: descifra su clave AES con la privada y, con ella, su nombre
    private static DetalleArchivo detalle(ArchivoRemoto remoto, String usuario, PrivateKey privada) {
        String nombre;
        try {
            byte[] k = CifradoRSA.descifrarClaveAES(remoto.claveAESCifrada(), privada);
            try {
                nombre = descifrarNombre(remoto.nombreCifrado(), k);
            } finally {
                Arrays.fill(k, (byte) 0);
            }
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            nombre = "(archivo dañado " + remoto.id().substring(0, 8) + ")";
        }
        return new DetalleArchivo(remoto.id(), nombre, remoto.emisor(), usuario.equals(remoto.emisor()),
                remoto.claveAESCifrada(), remoto.nombreCifrado(), remoto.firma());
    }

    // Mejora opcional de la guía (4.1): el nombre original también va cifrado con la clave del archivo,
    // así el servidor no sabe cómo se llaman los archivos. nombreCifrado = Base64(IV ‖ AES-CTR(K, nombre))
    private static String cifrarNombre(String nombre, byte[] k) throws GeneralSecurityException {
        return Base64.getEncoder().encodeToString(CifradorAES.cifrar(nombre.getBytes(StandardCharsets.UTF_8), k));
    }

    private static String descifrarNombre(String nombreCifrado, byte[] k) throws GeneralSecurityException {
        return nombreSeguro(new String(CifradorAES.descifrar(Base64.getDecoder().decode(nombreCifrado), k), StandardCharsets.UTF_8));
    }

    // El nombre lo pone quien envía el archivo: se quitan caracteres que no valen en Windows o que podrían
    // sacar el archivo de la carpeta elegida
    static String nombreSeguro(String nombre) {
        String limpio = nombre.replaceAll("[\\\\/:*?\"<>|\\p{Cntrl}]", "_").trim();
        while (limpio.startsWith(".")) {
            limpio = limpio.substring(1);
        }
        if (limpio.length() > 200) {
            limpio = limpio.substring(limpio.length() - 200);
        }
        return limpio.isBlank() ? "archivo" : limpio;
    }

    // La pública que devuelve el servidor tiene que ser la pareja de la privada (mismo módulo RSA)
    private static void comprobarPareja(PrivateKey privada, PublicKey publica) throws GeneralSecurityException {
        if (!(privada instanceof RSAPrivateCrtKey crt) || !(publica instanceof RSAPublicKey pub) || !crt.getModulus().equals(pub.getModulus())) {
            throw new GeneralSecurityException("La clave pública del servidor no corresponde con tu clave privada");
        }
    }

    // Si ya existe un archivo con ese nombre se añade (1), (2)...
    private static Path rutaLibre(Path carpeta, String nombreOriginal) {
        String nombre = nombreSeguro(nombreOriginal);
        Path destino = carpeta.resolve(nombre);
        int n = 1;
        while (Files.exists(destino)) {
            int punto = nombre.lastIndexOf('.');
            String base = punto > 0 ? nombre.substring(0, punto) : nombre;
            String ext = punto > 0 ? nombre.substring(punto) : "";
            destino = carpeta.resolve(base + " (" + n++ + ")" + ext);
        }
        return destino;
    }
}
