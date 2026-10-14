package cliente.interfaz;

import javax.swing.SwingUtilities;

public class AppCliente {

    public static void main(String[] args) {
        String
        SwingUtilities.invokeLater(() -> {
            Estilo.aplicarLookAndFeel();
            new VentanaLogin(servidor).setVisible(true);
        });
    }
}