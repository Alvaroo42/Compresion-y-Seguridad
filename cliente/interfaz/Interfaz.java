package cliente.interfaz;

import cliente.servicio.ServicioCifrado.DetalleArchivo;
import cliente.servicio.SesionLocal;

import javax.swing.*;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.nio.file.Path;
import java.util.List;

public class Interfaz {

    private SesionLocal sesion;
    private JFrame ventana;
    private final DefaultListModel<DetalleArchivo> modelo = new DefaultListModel<>();
    private final JList<DetalleArchivo> lista = new JList<>(modelo);

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new Interfaz().pedirAcceso());
    }

    // Pedir usuario y contraseña
    private void pedirAcceso() {
        JTextField campoUsuario = new JTextField(15);
        JPasswordField campoContrasena = new JPasswordField(15);
        JPanel panel = new JPanel(new java.awt.GridLayout(0, 1, 0, 4));

        panel.add(new JLabel("Usuario:"));
        panel.add(campoUsuario);
        panel.add(new JLabel("Contraseña (mínimo 4 caracteres):"));
        panel.add(campoContrasena);

        String[] opciones = {"Entrar", "Registrarse"};
        int eleccion = JOptionPane.showOptionDialog(null, panel, "Almacén seguro", JOptionPane.DEFAULT_OPTION, JOptionPane.PLAIN_MESSAGE, null, opciones, opciones[0]);
        if (eleccion != 0 && eleccion != 1) {
            System.exit(0);
        }

        String usuario = campoUsuario.getText().trim();
        char[] contrasena = campoContrasena.getPassword();
        SesionLocal nueva = new SesionLocal();
        
        try {
            if (eleccion == 1) {
                nueva.registrar(usuario, contrasena);
            }
            nueva.iniciarSesion(usuario, contrasena);
            sesion = nueva;
            abrirVentanaPrincipal();
        } catch (Exception e) {
            JOptionPane.showMessageDialog(null, "Error al acceder. Compruebe sus credenciales o inténtelo de nuevo.", "Error de autenticación", JOptionPane.ERROR_MESSAGE);
            pedirAcceso();
        } finally {
            java.util.Arrays.fill(contrasena, '\0');
        }
    }

    // Ventana principal de uso
    private void abrirVentanaPrincipal() {
        JButton botonCifrar = new JButton("Cifrar archivo...");
        JButton botonDescifrar = new JButton("Descifrar seleccionado...");
        JButton botonSalir = new JButton("Cerrar sesión");
        JPanel botones = new JPanel(new FlowLayout(FlowLayout.LEFT));

        botonCifrar.addActionListener(e -> cifrar());
        botonDescifrar.addActionListener(e -> descifrar());
        botonSalir.addActionListener(e -> cerrarSesion());
        botones.add(botonCifrar);
        botones.add(botonDescifrar);
        botones.add(botonSalir);

        ventana = new JFrame("Almacén seguro - usuario: " + sesion.getUsuario());
        ventana.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        ventana.add(botones, BorderLayout.NORTH);
        ventana.add(new JScrollPane(lista), BorderLayout.CENTER);
        ventana.setSize(700, 320);
        ventana.setLocationRelativeTo(null);
        ventana.setVisible(true);

        actualizarLista();
    }

    // Elige un archivo y lo cifra con una clave AES nueva
    private void cifrar() {
        JFileChooser selector = new JFileChooser();

        if (selector.showOpenDialog(ventana) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        try {
            sesion.cifrar(selector.getSelectedFile().toPath());
            actualizarLista();
        } catch (Exception e) {
            mostrarError();
        }
    }

    // Descifra el archivo seleccionado en la carpeta que elija el usuario
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
            JOptionPane.showMessageDialog(ventana, "Archivo descifrado exitosamente en:\n" + resultado);
        } catch (Exception e) {
            mostrarError();
        }
    }

    // Cerrar Sesion
    private void cerrarSesion() {
        sesion.close();
        ventana.dispose();
        modelo.clear();
        pedirAcceso();
    }

    // Actualizar lista de archivos cifrados
    private void actualizarLista() {
        try {
            List<DetalleArchivo> archivos = sesion.listar();
            modelo.clear();
            for (DetalleArchivo a : archivos) {
                modelo.addElement(a);
            }
        } catch (Exception e) {
            mostrarError();
        }
    }

    // Mostrar mensaje de error
    private void mostrarError() {
        JOptionPane.showMessageDialog(ventana, "Ha ocurrido un error inesperado al procesar la solicitud.", "Error de procesamiento", JOptionPane.ERROR_MESSAGE);
    }
}