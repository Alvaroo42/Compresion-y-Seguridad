package Cliente;

import Cliente.criptografia.CifradorBasico;
import Cliente.criptografia.HashUtils;
import Cliente.criptografia.CifradoRSA;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Base64;

public class Main {
    public static void main(String[] args) {
        try {
            // ==========================================
            // PARTE 1: CIFRADO SIMÉTRICO (El archivo)
            // ==========================================
            byte[] datosEnClaro = "Datos de prueba para el archivo multimedia".getBytes();
            byte[] clave16Bytes = new byte[16];
            new SecureRandom().nextBytes(clave16Bytes); 
            
            byte[] criptograma = CifradorBasico.cifrar(datosEnClaro, clave16Bytes);

            System.out.println("--- 1. PROCESO DE ARCHIVO (AES) ---");
            System.out.println("Clave AES Original (Base64): " + Base64.getEncoder().encodeToString(clave16Bytes));
            System.out.println("Archivo Cifrado (Base64): " + Base64.getEncoder().encodeToString(criptograma));

            // ==========================================
            // PARTE 2: PROTECCIÓN DE LA CLAVE (RSA)
            // ==========================================
            System.out.println("\n--- 2. PROTECCIÓN DE CLAVE (RSA) ---");
            
            // A) Generamos el par de claves del usuario (Pública y Privada)
            KeyPair parClavesUsuario = CifradoRSA.generarParClaves();
            
            // B) Ciframos la clave AES (la de 16 bytes) usando la clave Pública RSA
            byte[] claveAESCifrada = CifradoRSA.cifrarClaveAES(clave16Bytes, parClavesUsuario.getPublic());
            System.out.println("Clave AES Cifrada con RSA (Base64): " + Base64.getEncoder().encodeToString(claveAESCifrada));

            // C) Comprobación: Desciframos con la clave Privada para asegurar que recuperamos la misma AES
            byte[] claveAESRecuperada = CifradoRSA.descifrarClaveAES(claveAESCifrada, parClavesUsuario.getPrivate());
            System.out.println("Clave AES Recuperada (Base64): " + Base64.getEncoder().encodeToString(claveAESRecuperada));

            // ==========================================
            // PARTE 3: PROTECCIÓN DE LA CLAVE PRIVADA (HASH + AES)
            // ==========================================
            System.out.println("\n--- 3. PROTECCIÓN DE CLAVE PRIVADA (SHA-3 + AES) ---");
            
            // A) Simulamos que el usuario introduce su contraseña por teclado
            String passwordUsuario = "MiSuperSecreta123!";
            
            // B) Derivamos la clave de 16 bytes usando vuestro HashUtils
            byte[] claveAESDesdePassword = HashUtils.derivarClaveDesdePassword(passwordUsuario);
            System.out.println("Clave derivada de password (Base64): " + Base64.getEncoder().encodeToString(claveAESDesdePassword));
            
            // C) Extraemos los bytes puros de la Clave Privada RSA generada en la Parte 2
            byte[] clavePrivadaEnBytes = parClavesUsuario.getPrivate().getEncoded();
            
            // D) Ciframos la Clave Privada RSA usando el AES de tu compañero y la clave del password
            byte[] clavePrivadaCifrada = CifradorBasico.cifrar(clavePrivadaEnBytes, claveAESDesdePassword);
            System.out.println("Clave Privada RSA Cifrada (Base64): " + Base64.getEncoder().encodeToString(clavePrivadaCifrada));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}