package servidor.manejadores;

import com.sun.net.httpserver.HttpExchange;
import comun.Protocolo;
import servidor.almacenamiento.AlmacenUsuarios;
import servidor.seguridad.GestorTokens;
import servidor.seguridad.HashClaveLogin;
import servidor.seguridad.VerificadorGoogle;
import servidor.seguridad.VerificadorGoogle.Identidad;

import java.nio.file.FileAlreadyExistsException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

/**
 * POST /REGISTRO (no protegido). Recibe usuario, claveLogin, clavePublica y clavePrivadaCifrada.
 * Guarda el hash Argon2id de la clave de login (nunca la clave) y las claves tal cual llegan: la privada ya
 * viene cifrada por el cliente con su clave de datos. 201 si se crea, 409 si el usuario ya existe.
 * Mejora: si llega un token de Google, la cuenta queda protegida con Google como segundo factor.
 */
public class ManejadorRegistro extends ManejadorBase {

    private final HashClaveLogin hash;
    private final VerificadorGoogle google;

    public ManejadorRegistro(AlmacenUsuarios almacen, GestorTokens tokens, HashClaveLogin hash, VerificadorGoogle google) {
        super("POST", almacen, tokens);
        this.hash = hash;
        this.google = google;
    }

    @Override
    protected void procesar(HttpExchange ex) throws Exception {
        Properties campos = leerCampos(ex);
        String usuario = campos.getProperty(Protocolo.CAMPO_USUARIO);
        if (!Protocolo.usuarioValido(usuario)) {
            throw new ErrorHttp(400, "Nombre de usuario no válido");
        }
        byte[] claveLogin = binario(campos.getProperty(Protocolo.CAMPO_CLAVE_LOGIN), Protocolo.TAM_CLAVE_LOGIN, Protocolo.TAM_CLAVE_LOGIN);
        byte[] clavePublica = binario(campos.getProperty(Protocolo.CAMPO_CLAVE_PUBLICA), 1, 4096);
        byte[] privadaCifrada = binario(campos.getProperty(Protocolo.CAMPO_CLAVE_PRIVADA_CIFRADA), 29, 8192);
        comprobarClavePublica(clavePublica);
        if (almacen.existe(usuario)) {
            throw new ErrorHttp(409, "El usuario ya existe");
        }

        // Mejora: segundo factor con Google
        Identidad identidad = null;
        String idToken = campos.getProperty(Protocolo.CAMPO_ID_TOKEN_GOOGLE);
        if (idToken != null) {
            if (google == null) {
                throw new ErrorHttp(503, "El inicio de sesión con Google no está configurado en el servidor");
            }
            try {
                identidad = google.verificar(idToken, campos.getProperty(Protocolo.CAMPO_NONCE_GOOGLE), "registro");
            } catch (VerificadorGoogle.TokenNoValido e) {
                System.out.println("  token de Google rechazado: " + e.getMessage());
                throw new ErrorHttp(401, "No se ha podido comprobar la cuenta de Google");
            }
            if (almacen.usuarioDeGoogle(identidad.sub()) != null) {
                throw new ErrorHttp(409, "Esa cuenta de Google ya está registrada con otro usuario");
            }
        }

        byte[] salt = HashClaveLogin.nuevoSalt();
        HashClaveLogin.Parametros p = HashClaveLogin.RECOMENDADOS;
        Base64.Encoder b64 = Base64.getEncoder();
        Map<String, String> perfil = new LinkedHashMap<>();
        perfil.put("usuario", usuario);
        perfil.put("algoritmo", HashClaveLogin.ALGORITMO);
        perfil.put("argon2.memoriaKiB", String.valueOf(p.memoriaKiB()));
        perfil.put("argon2.iteraciones", String.valueOf(p.iteraciones()));
        perfil.put("argon2.paralelismo", String.valueOf(p.paralelismo()));
        perfil.put("salt", b64.encodeToString(salt));
        perfil.put("hashLogin", b64.encodeToString(hash.calcular(claveLogin, salt, p)));
        perfil.put("clavePublica", b64.encodeToString(clavePublica));
        perfil.put("clavePrivadaCifrada", b64.encodeToString(privadaCifrada));
        if (identidad != null) {
            perfil.put("google.sub", identidad.sub());
            perfil.put("google.correo", identidad.correo().replaceAll("[^A-Za-z0-9@._+-]", ""));
        }

        try {
            almacen.crear(usuario, perfil);
        } catch (FileAlreadyExistsException e) {
            throw new ErrorHttp(409, "El usuario ya existe");
        }
        if (identidad != null && !almacen.vincularGoogle(identidad.sub(), usuario)) {
            almacen.borrar(usuario);
            throw new ErrorHttp(409, "Esa cuenta de Google ya está registrada con otro usuario");
        }
        responderTexto(ex, 201, "Usuario creado");
    }

    // La clave pública tiene que ser una clave RSA de al menos 2048 bits en formato X.509
    private static void comprobarClavePublica(byte[] x509) throws ErrorHttp {
        try {
            RSAPublicKey clave = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(x509));
            if (clave.getModulus().bitLength() < 2048) {
                throw new ErrorHttp(400, "La clave pública debe ser RSA de 2048 bits o más");
            }
        } catch (ErrorHttp e) {
            throw e;
        } catch (Exception e) {
            throw new ErrorHttp(400, "Clave pública no válida");
        }
    }
}
