package cliente.criptografia;

import java.security.SecureRandom;

public class GeneradorClaves {
    public static byte[] generarClaveAES128() {

        // Instanciar el generador seguro
        SecureRandom secureRandom = new SecureRandom();
        
        // Crear el arreglo de 16 bytes para AES128
        byte[] claveAleatoria = new byte[16];
        
        // Llenar el arreglo con bytes aleatorios seguros
        secureRandom.nextBytes(claveAleatoria);
        
        return claveAleatoria;
    }
}