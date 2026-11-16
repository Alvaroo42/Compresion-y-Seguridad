package comun;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Lector de JSON mínimo, solo para lo que devuelve Google (tokens, claves públicas). Así no hace falta
 * ninguna librería: objetos → Map, listas → List, textos → String, números → Long o BigDecimal,
 * true/false → Boolean y null → null.
 */
public final class Json {

    private static final int PROFUNDIDAD_MAXIMA = 32;

    private final String texto;
    private int pos;

    private Json(String texto) {
        this.texto = texto;
    }

    public static Object leer(String texto) {
        Json lector = new Json(texto);
        Object valor = lector.valor(0);
        lector.espacios();
        if (lector.pos != texto.length()) {
            throw lector.error();
        }
        return valor;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> leerObjeto(String texto) {
        Object valor = leer(texto);
        if (!(valor instanceof Map)) {
            throw new IllegalArgumentException("Se esperaba un objeto JSON");
        }
        return (Map<String, Object>) valor;
    }

    private Object valor(int profundidad) {
        if (profundidad > PROFUNDIDAD_MAXIMA) {
            throw error();
        }
        espacios();
        if (pos >= texto.length()) {
            throw error();
        }
        char c = texto.charAt(pos);
        return switch (c) {
            case '{' -> objeto(profundidad);
            case '[' -> lista(profundidad);
            case '"' -> cadena();
            case 't' -> palabra("true", Boolean.TRUE);
            case 'f' -> palabra("false", Boolean.FALSE);
            case 'n' -> palabra("null", null);
            default -> numero();
        };
    }

    private Map<String, Object> objeto(int profundidad) {
        Map<String, Object> objeto = new LinkedHashMap<>();
        pos++;
        espacios();
        if (siguienteEs('}')) {
            return objeto;
        }
        do {
            espacios();
            if (pos >= texto.length() || texto.charAt(pos) != '"') {
                throw error();
            }
            String clave = cadena();
            espacios();
            esperar(':');
            objeto.put(clave, valor(profundidad + 1));
            espacios();
        } while (siguienteEs(','));
        esperar('}');
        return objeto;
    }

    private List<Object> lista(int profundidad) {
        List<Object> lista = new ArrayList<>();
        pos++;
        espacios();
        if (siguienteEs(']')) {
            return lista;
        }
        do {
            lista.add(valor(profundidad + 1));
            espacios();
        } while (siguienteEs(','));
        esperar(']');
        return lista;
    }

    private String cadena() {
        StringBuilder sb = new StringBuilder();
        pos++;
        while (pos < texto.length()) {
            char c = texto.charAt(pos++);
            if (c == '"') {
                return sb.toString();
            }
            if (c == '\\') {
                if (pos >= texto.length()) {
                    throw error();
                }
                char e = texto.charAt(pos++);
                switch (e) {
                    case '"', '\\', '/' -> sb.append(e);
                    case 'b' -> sb.append('\b');
                    case 'f' -> sb.append('\f');
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    case 't' -> sb.append('\t');
                    case 'u' -> {
                        if (pos + 4 > texto.length()) {
                            throw error();
                        }
                        try {
                            sb.append((char) Integer.parseInt(texto.substring(pos, pos + 4), 16));
                        } catch (NumberFormatException ex) {
                            throw error();
                        }
                        pos += 4;
                    }
                    default -> throw error();
                }
            } else if (c < 0x20) {
                throw error();
            } else {
                sb.append(c);
            }
        }
        throw error();
    }

    private Object numero() {
        int inicio = pos;
        while (pos < texto.length() && "+-0123456789.eE".indexOf(texto.charAt(pos)) >= 0) {
            pos++;
        }
        if (inicio == pos) {
            throw error();
        }
        try {
            BigDecimal numero = new BigDecimal(texto.substring(inicio, pos));
            try {
                return numero.longValueExact();
            } catch (ArithmeticException noEsEntero) {
                return numero;
            }
        } catch (NumberFormatException e) {
            throw error();
        }
    }

    private Object palabra(String palabra, Object valor) {
        if (!texto.startsWith(palabra, pos)) {
            throw error();
        }
        pos += palabra.length();
        return valor;
    }

    private void espacios() {
        while (pos < texto.length() && Character.isWhitespace(texto.charAt(pos))) {
            pos++;
        }
    }

    private boolean siguienteEs(char c) {
        if (pos < texto.length() && texto.charAt(pos) == c) {
            pos++;
            return true;
        }
        return false;
    }

    private void esperar(char c) {
        if (!siguienteEs(c)) {
            throw error();
        }
    }

    private IllegalArgumentException error() {
        return new IllegalArgumentException("JSON no válido (posición " + pos + ")");
    }
}
