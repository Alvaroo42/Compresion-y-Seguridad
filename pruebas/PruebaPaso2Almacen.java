package pruebas;

import comun.Protocolo;
import servidor.almacenamiento.AlmacenUsuarios;
import servidor.almacenamiento.AlmacenUsuarios.ArchivoGuardado;

import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.stream.Stream;

/** Paso 2 de la guía: el almacén del servidor, probado sin red. */
public class PruebaPaso2Almacen {

    public static void main(String[] args) throws Exception {
        Comprobaciones c = new Comprobaciones();
        Path datos = Files.createTempDirectory("almacen-");
        AlmacenUsuarios almacen = new AlmacenUsuarios(datos);

        Comprobaciones.apartado("Usuarios y perfil.properties");
        Map<String, String> perfil = new LinkedHashMap<>();
        perfil.put("usuario", "ana");
        perfil.put("algoritmo", "argon2id");
        perfil.put("salt", "Q2xhdmVBbGVhdG9yaWE=");
        almacen.crear("ana", perfil);
        c.comprobar("crear 'ana' crea su carpeta y su perfil", Files.isRegularFile(datos.resolve("usuarios/ana/perfil.properties")));
        c.comprobar("existe('ana') y no existe('luis')", almacen.existe("ana") && !almacen.existe("luis"));
        Properties leido = almacen.leerPerfil("ana");
        c.comprobar("el perfil se lee igual que se escribió", "argon2id".equals(leido.getProperty("algoritmo")) && "Q2xhdmVBbGVhdG9yaWE=".equals(leido.getProperty("salt")));
        System.out.println("     perfil.properties:\n       " + Files.readString(datos.resolve("usuarios/ana/perfil.properties")).replace("\n", "\n       ").trim());
        Throwable t = Comprobaciones.excepcionDe(() -> almacen.crear("ana", perfil));
        c.comprobar("crear 'ana' otra vez -> FileAlreadyExistsException (será el 409)", t instanceof FileAlreadyExistsException);

        Comprobaciones.apartado("Nombres de usuario");
        for (String malo : new String[]{"../evil", "..", "...", "a", "ana/luis", "ana\\luis", "con", "NUL.txt", "ana.", ".ana", "con espacio", "x".repeat(33)}) {
            c.comprobar("'" + malo + "' no es válido", !Protocolo.usuarioValido(malo) && Comprobaciones.excepcionDe(() -> almacen.crear(malo, perfil)) instanceof IllegalArgumentException);
        }
        for (String bueno : new String[]{"ana", "luis_2026", "maria.lopez", "a-b", "x".repeat(32)}) {
            c.comprobar("'" + bueno + "' sí es válido", Protocolo.usuarioValido(bueno));
        }

        Comprobaciones.apartado("Archivos .cif y .meta");
        Path temporal = almacen.nuevoTemporal("ana");
        Files.writeString(temporal, "SVYgfHwgQ09OVEVOSURPIENJRlJBRE8=");
        Map<String, String> meta = new LinkedHashMap<>();
        meta.put("nombre", "Zm90by5qcGc=");
        meta.put("claveAESCifrada", "Rk9QUA==");
        meta.put("emisor", "ana");
        String id = almacen.guardarArchivo("ana", temporal, meta);
        c.comprobar("el id generado es un UUID: " + id, Protocolo.idValido(id));
        c.comprobar("se guardan <id>.cif y <id>.meta en la carpeta de ana",
                Files.isRegularFile(datos.resolve("usuarios/ana/archivos/" + id + ".cif")) && Files.isRegularFile(datos.resolve("usuarios/ana/archivos/" + id + ".meta")));
        c.comprobar("el temporal ya no existe (se ha movido)", !Files.exists(temporal));
        List<ArchivoGuardado> lista = almacen.listar("ana");
        c.comprobar("la lista de ana tiene ese archivo con su emisor", lista.size() == 1 && lista.get(0).id().equals(id) && "ana".equals(lista.get(0).meta().getProperty("emisor")));
        c.comprobar("rutaCif devuelve el .cif de ana", almacen.rutaCif("ana", id) != null);

        almacen.crear("luis", perfil);
        c.comprobar("luis no puede pedir el id de ana (rutaCif = null -> 404)", almacen.rutaCif("luis", id) == null);
        c.comprobar("un id con ../ no es válido (rutaCif = null)", almacen.rutaCif("ana", "../luis/perfil.properties") == null);
        c.comprobar("un id inventado no existe", almacen.rutaCif("ana", "00000000-0000-0000-0000-000000000000") == null);
        c.comprobar("la lista de luis está vacía", almacen.listar("luis").isEmpty());

        Comprobaciones.apartado("Cuentas de Google (mejora)");
        c.comprobar("vincular una cuenta de Google con ana", almacen.vincularGoogle("1094512345", "ana"));
        c.comprobar("la misma cuenta de Google no se puede vincular con luis", !almacen.vincularGoogle("1094512345", "luis"));
        c.comprobar("usuarioDeGoogle devuelve ana", "ana".equals(almacen.usuarioDeGoogle("1094512345")));

        try (Stream<Path> todo = Files.walk(datos)) {
            c.comprobar("no quedan ficheros temporales", todo.noneMatch(p -> p.getFileName().toString().endsWith(".tmp")));
        }
        c.terminar("Paso 2");
    }
}
