package servidor.manejadores;

import com.sun.net.httpserver.HttpExchange;
import comun.Protocolo;
import servidor.almacenamiento.AlmacenUsuarios;
import servidor.almacenamiento.AlmacenUsuarios.ArchivoGuardado;
import servidor.seguridad.GestorTokens;
import servidor.seguridad.HashClaveLogin;
import servidor.seguridad.VerificadorGoogle;
import servidor.seguridad.VerificadorGoogle.Identidad;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * POST /LOGIN (no protegido). Recibe usuario y claveLogin. Si el hash Argon2id coincide devuelve el token de
 * sesión, la clave pública, la privada cifrada y la lista de archivos (solo metadatos: el contenido se pide
 * con /BAJAR). Si falla, 401 con un mensaje genérico que no dice si el usuario existe.
 * Mejora: si la cuenta está protegida con Google, además hace falta un token de Google de esa misma cuenta.
 */
public class ManejadorLogin extends ManejadorBase {

    public static final String MENSAJE_INCORRECTO = "Usuario o clave incorrectos";

    private final HashClaveLogin hash;
    private final VerificadorGoogle google;

    public ManejadorLogin(AlmacenUsuarios almacen, GestorTokens tokens, HashClaveLogin hash, VerificadorGoogle google) {
        super("POST", almacen, tokens);
        this.hash = hash;
        this.google = google;
    }

    @Override
    protected void procesar(HttpExchange ex) throws Exception {
        Properties campos = leerCampos(ex);
        String usuario = campos.getProperty(Protocolo.CAMPO_USUARIO);
        byte[] claveLogin = binario(campos.getProperty(Protocolo.CAMPO_CLAVE_LOGIN), Protocolo.TAM_CLAVE_LOGIN, Protocolo.TAM_CLAVE_LOGIN);

        Properties perfil = Protocolo.usuarioValido(usuario) ? almacen.leerPerfil(usuario) : null;
        if (perfil == null) {
            hash.verificarFalso(claveLogin);   // mismo tiempo de respuesta que con un usuario real
            throw new ErrorHttp(401, MENSAJE_INCORRECTO);
        }
        Base64.Decoder b64 = Base64.getDecoder();
        HashClaveLogin.Parametros p = new HashClaveLogin.Parametros(
                Integer.parseInt(perfil.getProperty("argon2.memoriaKiB")),
                Integer.parseInt(perfil.getProperty("argon2.iteraciones")),
                Integer.parseInt(perfil.getProperty("argon2.paralelismo")));
        if (!HashClaveLogin.ALGORITMO.equals(perfil.getProperty("algoritmo"))
                || !hash.verificar(claveLogin, b64.decode(perfil.getProperty("salt")), p, b64.decode(perfil.getProperty("hashLogin")))) {
            throw new ErrorHttp(401, MENSAJE_INCORRECTO);
        }

        // Mejora: segundo factor. Solo se llega aquí con la contraseña correcta, así que decir que la cuenta
        // usa Google no revela nada a quien no la conozca.
        String subGoogle = perfil.getProperty("google.sub");
        if (subGoogle != null) {
            String idToken = campos.getProperty(Protocolo.CAMPO_ID_TOKEN_GOOGLE);
            if (idToken == null) {
                throw new ErrorHttp(403, "Esta cuenta está protegida con Google", Protocolo.CABECERA_REQUIERE_GOOGLE, "si");
            }
            if (google == null) {
                throw new ErrorHttp(503, "El inicio de sesión con Google no está configurado en el servidor");
            }
            Identidad identidad;
            try {
                identidad = google.verificar(idToken, campos.getProperty(Protocolo.CAMPO_NONCE_GOOGLE), "login");
            } catch (VerificadorGoogle.TokenNoValido e) {
                System.out.println("  token de Google rechazado: " + e.getMessage());
                throw new ErrorHttp(401, "No se ha podido comprobar la cuenta de Google");
            }
            if (!subGoogle.equals(identidad.sub())) {
                throw new ErrorHttp(401, "Esa cuenta de Google no es la de este usuario");
            }
        }

        Map<String, String> respuesta = new LinkedHashMap<>();
        respuesta.put(Protocolo.CAMPO_TOKEN, tokens.crear(usuario));
        respuesta.put(Protocolo.CAMPO_VALIDEZ_TOKEN, String.valueOf(tokens.validez().toSeconds()));
        respuesta.put(Protocolo.CAMPO_CLAVE_PUBLICA, perfil.getProperty("clavePublica"));
        respuesta.put(Protocolo.CAMPO_CLAVE_PRIVADA_CIFRADA, perfil.getProperty("clavePrivadaCifrada"));
        if (subGoogle != null) {
            respuesta.put(Protocolo.CAMPO_CORREO_GOOGLE, perfil.getProperty("google.correo", ""));
        }
        anadirLista(respuesta, almacen.listar(usuario));
        responderCampos(ex, 200, respuesta);
    }

    // archivos=N y, por cada uno, archivo.i.id / .nombre / .claveAESCifrada / .emisor (/ .firma)
    static void anadirLista(Map<String, String> respuesta, List<ArchivoGuardado> archivos) {
        respuesta.put(Protocolo.CAMPO_ARCHIVOS, String.valueOf(archivos.size()));
        for (int i = 0; i < archivos.size(); i++) {
            ArchivoGuardado a = archivos.get(i);
            String prefijo = Protocolo.PREFIJO_ARCHIVO + i;
            respuesta.put(prefijo + Protocolo.SUFIJO_ID, a.id());
            respuesta.put(prefijo + Protocolo.SUFIJO_NOMBRE, a.meta().getProperty("nombre", ""));
            respuesta.put(prefijo + Protocolo.SUFIJO_CLAVE_AES, a.meta().getProperty("claveAESCifrada", ""));
            respuesta.put(prefijo + Protocolo.SUFIJO_EMISOR, a.meta().getProperty("emisor", ""));
            if (a.meta().getProperty("firma") != null) {
                respuesta.put(prefijo + Protocolo.SUFIJO_FIRMA, a.meta().getProperty("firma"));
            }
        }
    }
}
