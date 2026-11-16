package pruebas;

/** Utilidades mínimas para las pruebas: cada comprobación imprime OK o FALLO y se cuentan al final. */
public class Comprobaciones {

    private int correctas = 0;
    private int fallidas = 0;

    public interface Accion {
        void ejecutar() throws Exception;
    }

    public void comprobar(String descripcion, boolean condicion) {
        System.out.println((condicion ? "  OK     " : "  FALLO  ") + descripcion);
        if (condicion) {
            correctas++;
        } else {
            fallidas++;
        }
    }

    // Ejecuta la acción y devuelve la excepción que lanza (o null si no lanza ninguna)
    public static Throwable excepcionDe(Accion accion) {
        try {
            accion.ejecutar();
            return null;
        } catch (Throwable t) {
            return t;
        }
    }

    public static void apartado(String titulo) {
        System.out.println("\n" + titulo);
    }

    // Imprime el resumen y termina con código 0 si todo ha ido bien
    public void terminar(String prueba) {
        System.out.println("\n" + prueba + ": " + correctas + " correctas, " + fallidas + " fallidas");
        System.exit(fallidas == 0 ? 0 : 1);
    }
}
