package cliente.interfaz;

import cliente.servicio.ServicioCifrado.DetalleArchivo;
import cliente.servicio.SesionLocal;

import javax.swing.*;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.nio.file.Path;
import java.util.List;

/**
 * Interfaz básica en un único archivo (Swing estándar, sin librerías).
 *
 * Flujo:
 *   1. Ventana de acceso (JOptionPane): usuario + contraseña -> Entrar o Registrarse.
 *   2. Ventana principal: lista de archivos cifrados, botones Cifrar / Descifrar / Cerrar sesión
 *      y una caja de texto con los pasos criptográficos que va haciendo el programa.
 *
 * Toda la criptografía está en cliente.servicio (SesionLocal): esta clase solo muestra
 * ventanas y llama a sus métodos registrar(), iniciarSesion(), cifrar(), listar() y descifrar().
 *
 * Ejecutar:  java -cp out cliente.interfaz.Interfaz
 */
public class Interfaz {

    private SesionLocal sesion;                                  // usuario que ha entrado
    private JFrame ventana;
    private final DefaultListModel<DetalleArchivo> modelo = new DefaultListModel<>();
    private final JList<DetalleArchivo> lista = new JList<>(modelo);
    private final JTextArea registro = new JTextArea();          // pasos criptográficos

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new Interfaz().pedirAcceso());
    }

    // ------------------------------------------------------------------
    // 1. Acceso
    // ------------------------------------------------------------------

    /** Pide usuario y contraseña. Se repite hasta que entre bien o pulse Salir. */
    private void pedirAcceso() {
        JTextField campoUsuario = new JTextField(15);
        JPasswordField campoContrasena = new JPasswordField(15);
        JPanel panel = new JPanel(new java.awt.GridLayout(0, 1, 0, 4));
        panel.add(new JLabel("Usuario:"));
        panel.add(campoUsuario);
        panel.add(new JLabel("Contraseña (mínimo 4 caracteres):"));
        panel.add(campoContrasena);

        String[] opciones = {"Entrar", "Registrarse", "Salir"};
        int eleccion = JOptionPane.showOptionDialog(null, panel, "Almacén seguro",
                JOptionPane.DEFAULT_OPTION, JOptionPane.PLAIN_MESSAGE, null, opciones, opciones[0]);
        if (eleccion != 0 && eleccion != 1) {
            System.exit(0);                                      // Salir o cerrar la ventana
        }

        String usuario = campoUsuario.getText().trim();
        char[] contrasena = campoContrasena.getPassword();
        SesionLocal nueva = new SesionLocal();
        nueva.setRegistro(texto -> SwingUtilities.invokeLater(() -> registro.append(texto + "\n")));
        try {
            if (eleccion == 1) {
                nueva.registrar(usuario, contrasena);            // crea RSA y protege la clave privada
            }
            nueva.iniciarSesion(usuario, contrasena);            // descifra la clave privada con la contraseña
            sesion = nueva;
            abrirVentanaPrincipal();
        } catch (Exception e) {
            JOptionPane.showMessageDialog(null, e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            pedirAcceso();                                       // volver a pedirlo
        } finally {
            java.util.Arrays.fill(contrasena, '\0');             // borrar la contraseña de memoria
        }
    }

    // ------------------------------------------------------------------
    // 2. Ventana principal
    // ------------------------------------------------------------------

    private void abrirVentanaPrincipal() {
        JButton botonCifrar = new JButton("Cifrar archivo...");
        JButton botonDescifrar = new JButton("Descifrar seleccionado...");
        JButton botonSalir = new JButton("Cerrar sesión");
        botonCifrar.addActionListener(e -> cifrar());
        botonDescifrar.addActionListener(e -> descifrar());
        botonSalir.addActionListener(e -> cerrarSesion());

        JPanel botones = new JPanel(new FlowLayout(FlowLayout.LEFT));
        botones.add(botonCifrar);
        botones.add(botonDescifrar);
        botones.add(botonSalir);

        registro.setEditable(false);
        JScrollPane cajaRegistro = new JScrollPane(registro);
        cajaRegistro.setPreferredSize(new java.awt.Dimension(700, 200));

        ventana = new JFrame("Almacén seguro - usuario: " + sesion.getUsuario());
        ventana.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        ventana.add(botones, BorderLayout.NORTH);
        ventana.add(new JScrollPane(lista), BorderLayout.CENTER);
        ventana.add(cajaRegistro, BorderLayout.SOUTH);
        ventana.setSize(700, 520);
        ventana.setLocationRelativeTo(null);
        ventana.setVisible(true);

        actualizarLista();
    }

    /** Elige un archivo y lo cifra con una clave AES nueva. */
    private void cifrar() {
        JFileChooser selector = new JFileChooser();
        if (selector.showOpenDialog(ventana) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        try {
            sesion.cifrar(selector.getSelectedFile().toPath());
            actualizarLista();
        } catch (Exception e) {
            mostrarError(e);
        }
    }

    /** Descifra el archivo seleccionado en la carpeta que elija el usuario. */
    private void descifrar() {
        DetalleArchivo elegido = lista.getSelectedValue();
        if (elegido == null) {
            JOptionPane.showMessageDialog(ventana, "Selecciona un archivo de la lista.");
            return;
        }
        JFileChooser selector = new JFileChooser();
        selector.setDialogTitle("Carpeta donde guardar el archivo descifrado");
        selector.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        if (selector.showSaveDialog(ventana) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        try {
            Path resultado = sesion.descifrar(elegido.id(), selector.getSelectedFile().toPath());
            JOptionPane.showMessageDialog(ventana, "Archivo descifrado en:\n" + resultado);
        } catch (Exception e) {
            mostrarError(e);
        }
    }

    private void cerrarSesion() {
        sesion.close();                                          // olvida la clave privada
        ventana.dispose();
        modelo.clear();
        registro.setText("");
        pedirAcceso();
    }

    // ------------------------------------------------------------------
    // Auxiliares
    // ------------------------------------------------------------------

    private void actualizarLista() {
        try {
            List<DetalleArchivo> archivos = sesion.listar();
            modelo.clear();
            for (DetalleArchivo a : archivos) {
                modelo.addElement(a);
            }
        } catch (Exception e) {
            mostrarError(e);
        }
    }

    private void mostrarError(Exception e) {
        JOptionPane.showMessageDialog(ventana, e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
    }
}
