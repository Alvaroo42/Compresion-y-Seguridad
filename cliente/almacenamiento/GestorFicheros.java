package cliente.almacenamiento;

import java.io.FileOutputStream;
import java.io.File;

public class GestorFicheros {
    public static void guardarClavesUsuario(String nombreUsuario, byte[] clavePublica, byte[] clavePrivadaCifrada) throws Exception {
        
        // Guardamos la Clave Pública RSA en claro
        File archPublica = new File(nombreUsuario + "_publica.key");
        try (FileOutputStream fosPub = new FileOutputStream(archPublica)) {
            fosPub.write(clavePublica);
            System.out.println("Clave pública guardada en: " + archPublica.getAbsolutePath());
        }

        // Guardamos la Clave Privada RSA cifrada
        File archPrivada = new File(nombreUsuario + "_privada.cif");
        try (FileOutputStream fosPriv = new FileOutputStream(archPrivada)) {
            fosPriv.write(clavePrivadaCifrada);
            System.out.println("Clave privada protegida guardada en: " + archPrivada.getAbsolutePath());
        }
    }
}