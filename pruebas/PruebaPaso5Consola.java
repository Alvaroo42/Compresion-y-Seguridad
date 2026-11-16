package pruebas;

import cliente.red.ClienteServidor;
import cliente.servicio.ServicioCifrado;
import cliente.servicio.ServicioCifrado.DetalleArchivo;
import cliente.servicio.SesionRemota;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;

/**
 * Pasos 5 y 6 de la guía: registro, login, subir y bajar desde la consola contra un servidor HTTPS que ya está
 * en marcha (otro proceso). Uso: java pruebas.PruebaPaso5Consola localhost:8443 cliente_confianza.p12
 */
public class PruebaPaso5Consola {

    public static void main(String[] args) throws Exception {
        Comprobaciones c = new Comprobaciones();
        String servidor = args[0];
        Path confianza = Path.of(args[1]);
        Path carpeta = Files.createTempDirectory("consola-");

        SesionRemota ana = nuevaSesion(servidor, confianza);
        SesionRemota luis = nuevaSesion(servidor, confianza);
        Comprobaciones.apartado("Registro e inicio de sesión");
        ana.registrar("ana", "clave-de-ana".toCharArray(), null);
        luis.registrar("luis", "clave-de-luis".toCharArray(), null);
        c.comprobar("registrados ana y luis", true);
        List<DetalleArchivo> lista = ana.iniciarSesion("ana", "clave-de-ana".toCharArray(), null);
        c.comprobar("ana inicia sesión (0 archivos)", lista.isEmpty());

        Comprobaciones.apartado("Cifrar y subir, bajar y descifrar");
        Path foto = carpeta.resolve("foto playa.jpg");
        byte[] contenido = new byte[2_000_000];
        new java.util.Random(1).nextBytes(contenido);
        Files.write(foto, contenido);
        DetalleArchivo subido = ana.cifrar(foto);
        System.out.println("     subido: " + subido.nombre() + " -> id " + subido.id());
        Path descifrado = ana.descifrar(subido, carpeta.resolve("descargas"));
        c.comprobar("ana baja y descifra: el archivo es idéntico (SHA-256)", resumen(descifrado).equals(resumen(foto)));

        Comprobaciones.apartado("Compartir");
        ana.compartir(subido, "luis");
        List<DetalleArchivo> deLuis = luis.iniciarSesion("luis", "clave-de-luis".toCharArray(), null);
        System.out.println("     lista de luis: " + deLuis);
        c.comprobar("luis ve la foto compartida por ana", deLuis.size() == 1 && deLuis.get(0).emisor().equals("ana"));
        Path deAna = luis.descifrar(deLuis.get(0), carpeta.resolve("descargas-luis"));
        c.comprobar("luis la descifra con SU clave privada: idéntica", resumen(deAna).equals(resumen(foto)));

        ana.close();
        luis.close();
        c.terminar("Pasos 5-6 (consola)");
    }

    private static SesionRemota nuevaSesion(String servidor, Path confianza) throws Exception {
        return new SesionRemota(new ServicioCifrado(new ClienteServidor(servidor, confianza, "cys-confianza".toCharArray())));
    }

    private static String resumen(Path archivo) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(archivo)));
    }
}
