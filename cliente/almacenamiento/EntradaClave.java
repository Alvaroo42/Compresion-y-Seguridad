package cliente.almacenamiento;

/**
 * Una entrada del almacén de claves: la clave AES de un archivo, cifrada con la
 * clave pública RSA de un usuario.
 *
 * En la Fase 2, compartir un archivo = añadir otra entrada con el mismo idArchivo
 * y la clave AES cifrada con la PU del destinatario.
 */
public final class EntradaClave {

    private final String idArchivo;
    private final String usuario;
    private final String nombreOriginal;
    private final byte[] claveCifrada;

    public EntradaClave(String idArchivo, String usuario, String nombreOriginal, byte[] claveCifrada) {
        this.idArchivo = idArchivo;
        this.usuario = usuario;
        this.nombreOriginal = nombreOriginal;
        this.claveCifrada = claveCifrada.clone();
    }

    public String getIdArchivo()      { return idArchivo; }
    public String getUsuario()        { return usuario; }
    public String getNombreOriginal() { return nombreOriginal; }
    public byte[] getClaveCifrada()   { return claveCifrada.clone(); }

    @Override
    public String toString() {
        return nombreOriginal + "  [id: " + idArchivo + "]";
    }
}
