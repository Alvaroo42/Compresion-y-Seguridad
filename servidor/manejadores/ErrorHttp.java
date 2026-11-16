package servidor.manejadores;

/** Error que se devuelve al cliente con un código HTTP y un mensaje que se puede enseñar al usuario. */
public class ErrorHttp extends Exception {

    private static final long serialVersionUID = 1L;
    private final int estado;
    private final String cabecera;
    private final String valorCabecera;

    public ErrorHttp(int estado, String mensaje) {
        this(estado, mensaje, null, null);
    }

    // Error con una cabecera extra en la respuesta (por ejemplo Requiere-Google)
    public ErrorHttp(int estado, String mensaje, String cabecera, String valorCabecera) {
        super(mensaje);
        this.estado = estado;
        this.cabecera = cabecera;
        this.valorCabecera = valorCabecera;
    }

    public int estado() {
        return estado;
    }

    public String cabecera() {
        return cabecera;
    }

    public String valorCabecera() {
        return valorCabecera;
    }
}
