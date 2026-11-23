package servidor.manejadores;

/** Error que se devuelve al cliente con un código HTTP y un mensaje que se puede enseñar al usuario. */
public class ErrorHttp extends Exception {

    private static final long serialVersionUID = 1L;
    private final int estado;

    public ErrorHttp(int estado, String mensaje) {
        super(mensaje);
        this.estado = estado;
    }

    public int estado() {
        return estado;
    }
}
