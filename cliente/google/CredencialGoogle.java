package cliente.google;

/**
 * Lo que devuelve Google al terminar el inicio de sesión: el ID token (JWT firmado por Google), el nonce que
 * generó el cliente para ese inicio de sesión y el correo de la cuenta (solo para mostrarlo). Quien comprueba
 * de verdad el token es el servidor.
 */
public record CredencialGoogle(String idToken, String nonce, String correo) {
}
