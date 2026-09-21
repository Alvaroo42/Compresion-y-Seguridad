package Cliente.Almacenamiento;

import java.io.FileOutputStream;
import java.io.File;

public class GestorFicheros {

    /**
     * Guarda las claves del usuario en el disco duro.
     * @param nombreUsuario Nombre para identificar los archivos del usuario
     * @param clavePublica La clave pública en claro (para compartir en Fase 2)
     * @param clavePrivadaCifrada La clave privada blindada con AES y SHA-3
     */
    public static void guardarClavesUsuario(String nombreUsuario, byte[] clavePublica, byte[] clavePrivadaCifrada) throws Exception {
        
        // 1. Guardamos la Clave Pública RSA en claro
        File archPublica = new File(nombreUsuario + "_publica.key");
        try (FileOutputStream fosPub = new FileOutputStream(archPublica)) {
            fosPub.write(clavePublica);
            System.out.println("Clave pública guardada en: " + archPublica.getAbsolutePath());
        }

        // 2. Guardamos la Clave Privada RSA cifrada[cite: 1, 2]
        File archPrivada = new File(nombreUsuario + "_privada.cif");
        try (FileOutputStream fosPriv = new FileOutputStream(archPrivada)) {
            fosPriv.write(clavePrivadaCifrada);
            System.out.println("Clave privada protegida guardada en: " + archPrivada.getAbsolutePath());
        }
    }
}