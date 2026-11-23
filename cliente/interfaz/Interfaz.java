package cliente.interfaz;

import cliente.criptografia.FirmaDigital.FirmaNoValidaException;
import cliente.criptografia.ProtectorClavePrivada.ContrasenaIncorrectaException;
import cliente.google.CredencialGoogle;
import cliente.google.InicioGoogle;
import cliente.red.ClienteServidor;
import cliente.red.ClienteServidor.ErrorServidor;
import cliente.servicio.ServicioCifrado;
import cliente.servicio.ServicioCifrado.DetalleArchivo;
import cliente.servicio.SesionRemota;
import comun.ConfiguracionGoogle;

import javax.net.ssl.SSLException;
import javax.swing.*;
import java.awt.BorderLayout;
import java.awt.Cursor;
import java.awt.Desktop;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.net.ConnectException;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpTimeoutException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;

/**
 * Interfaz Swing del cliente. Toda la criptografía se hace en este equipo (SesionRemota → ServicioCifrado);
 * al servidor solo le llega lo que ya va cifrado. Lo que usa la red se ejecuta en segundo plano para que la
 * ventana no se congele con archivos grandes.
 *
 * Opciones (java -D...): cys.servidor (localhost:8443 por defecto), cys.confianza (cliente_confianza.p12),
 * cys.google (google_oauth.properties) y cys.abrir=false para no abrir los archivos al descifrarlos.
 */
public class Interfaz {

    private static final String TITULO = "Almacén seguro";

    private SesionRemota sesion;
    private String servidor = System.getProperty("cys.servidor", "localhost:8443");
    private JFrame ventana;
    private final DefaultListModel<DetalleArchivo> modelo = new DefaultListModel<>();
    private final JList<DetalleArchivo> lista = new JList<>(modelo);
    private final JLabel estado = new JLabel(" ");
    private final List<JButton> botones = new ArrayList<>();

    // Una operación que se ejecuta fuera del hilo de la interfaz
    private interface Tarea<T> {
        T ejecutar() throws Exception;
    }

    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());   // aspecto de Windows en Windows
        } catch (Exception e) {
            // se queda el aspecto por defecto de Java
        }
        SwingUtilities.invokeLater(() -> new Interfaz().pedirAcceso(""));
    }

    public Interfaz() {
        lista.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        lista.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && lista.isEnabled()) {
                    descifrar();
                }
            }
        });
        estado.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
    }

    // ------------------------------------------------------------------ acceso

    // Pide usuario, contraseña y servidor
    private void pedirAcceso(String usuarioPrevio) {
        JTextField campoUsuario = new JTextField(usuarioPrevio, 18);
        JPasswordField campoContrasena = new JPasswordField(18);
        JTextField campoServidor = new JTextField(servidor, 18);
        JPanel panel = new JPanel(new GridLayout(0, 1, 0, 4));
        panel.add(new JLabel("Usuario:"));
        panel.add(campoUsuario);
        panel.add(new JLabel("Contraseña (mínimo 8 caracteres):"));
        panel.add(campoContrasena);
        panel.add(new JLabel("Servidor (nombre:puerto):"));
        panel.add(campoServidor);

        String[] opciones = {"Entrar", "Registrarse", "Registrarse con Google"};
        int eleccion = JOptionPane.showOptionDialog(null, panel, TITULO, JOptionPane.DEFAULT_OPTION,
                JOptionPane.PLAIN_MESSAGE, null, opciones, opciones[0]);
        if (eleccion < 0) {
            System.exit(0);
        }
        String usuario = campoUsuario.getText().trim();
        char[] contrasena = campoContrasena.getPassword();
        servidor = campoServidor.getText().trim();

        boolean registrar = eleccion >= 1;
        boolean conGoogle = eleccion == 2;
        if (registrar && !confirmarRegistro(contrasena, conGoogle)) {
            Arrays.fill(contrasena, '\0');
            pedirAcceso(usuario);
            return;
        }
        acceder(registrar, conGoogle, usuario, contrasena);
    }

    // Al crear la cuenta se repite la contraseña y se avisa de que no se puede recuperar
    private boolean confirmarRegistro(char[] contrasena, boolean conGoogle) {
        JPasswordField repetida = new JPasswordField(18);
        JPanel panel = new JPanel(new GridLayout(0, 1, 0, 4));
        panel.add(new JLabel("Repite la contraseña:"));
        panel.add(repetida);
        panel.add(new JLabel(" "));
        panel.add(new JLabel("<html><b>Importante:</b> si olvidas la contraseña, nadie puede recuperar tus archivos,<br>"
                + "ni siquiera el administrador del servidor.</html>"));
        if (conGoogle) {
            panel.add(new JLabel("<html>Después se abrirá el navegador para elegir tu cuenta de Google.<br>"
                    + "A partir de entonces, para entrar harán falta la contraseña <b>y</b> esa cuenta de Google.</html>"));
        }
        if (JOptionPane.showConfirmDialog(null, panel, "Crear cuenta", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE) != JOptionPane.OK_OPTION) {
            return false;
        }
        char[] segunda = repetida.getPassword();
        boolean iguales = Arrays.equals(contrasena, segunda);
        Arrays.fill(segunda, '\0');
        if (!iguales) {
            JOptionPane.showMessageDialog(null, "Las contraseñas no coinciden.", "Crear cuenta", JOptionPane.WARNING_MESSAGE);
        }
        return iguales;
    }

    // Conecta con el servidor (y crea la cuenta si se ha pedido) con una ventana de espera
    private void acceder(boolean registrar, boolean conGoogle, String usuario, char[] contrasena) {
        Path confianza = Path.of(System.getProperty("cys.confianza", "cliente_confianza.p12"));
        if (!Files.isRegularFile(confianza)) {
            JOptionPane.showMessageDialog(null, "No se encuentra el certificado del servidor (" + confianza.toAbsolutePath()
                    + ").\nCópialo junto al programa: se genera en el servidor con GenerarCertificado.bat.", TITULO, JOptionPane.ERROR_MESSAGE);
            Arrays.fill(contrasena, '\0');
            pedirAcceso(usuario);
            return;
        }

        JLabel texto = new JLabel(registrar ? "Creando la cuenta (generando las claves RSA)..." : "Conectando con " + servidor + "...");
        JDialog espera = ventanaEspera(texto);
        SesionRemota[] nueva = new SesionRemota[1];
        SwingWorker<List<DetalleArchivo>, Void> trabajo = new SwingWorker<>() {
            @Override
            protected List<DetalleArchivo> doInBackground() throws Exception {
                try {
                    nueva[0] = new SesionRemota(new ServicioCifrado(new ClienteServidor(servidor, confianza, claveConfianza())));
                    CredencialGoogle google = null;
                    if (conGoogle) {
                        google = google(texto);
                    }
                    if (registrar) {
                        nueva[0].registrar(usuario, contrasena, google);
                        cambiarTexto(texto, "Cuenta creada. Entrando...");
                    }
                    try {
                        return nueva[0].iniciarSesion(usuario, contrasena, google);
                    } catch (ErrorServidor e) {
                        if (!e.requiereGoogle()) {
                            throw e;
                        }
                        // La contraseña es correcta y la cuenta usa Google como segundo factor
                        return nueva[0].iniciarSesion(usuario, contrasena, google(texto));
                    }
                } finally {
                    Arrays.fill(contrasena, '\0');
                }
            }

            @Override
            protected void done() {
                espera.dispose();
            }
        };
        JButton cancelar = new JButton("Cancelar");
        cancelar.addActionListener(e -> trabajo.cancel(true));
        JPanel pie = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        pie.add(cancelar);
        espera.add(pie, BorderLayout.SOUTH);
        espera.setSize(480, 160);
        espera.setLocationRelativeTo(null);
        trabajo.execute();
        espera.setVisible(true);   // es modal: vuelve cuando termina el trabajo

        if (trabajo.isCancelled()) {
            pedirAcceso(usuario);
            return;
        }
        try {
            List<DetalleArchivo> archivos = trabajo.get();
            sesion = nueva[0];
            if (registrar) {
                JOptionPane.showMessageDialog(null, "Cuenta creada. Recuerda tu contraseña: sin ella no se pueden recuperar tus archivos.",
                        TITULO, JOptionPane.INFORMATION_MESSAGE);
            }
            abrirVentanaPrincipal(archivos);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (ExecutionException e) {
            JOptionPane.showMessageDialog(null, mensajeDe(e.getCause(), true), "No se ha podido entrar", JOptionPane.ERROR_MESSAGE);
            pedirAcceso(usuario);
        }
    }

    // Mejora: inicio de sesión con Google en el navegador (se llama desde el hilo de fondo)
    private CredencialGoogle google(JLabel texto) throws Exception {
        ConfiguracionGoogle configuracion = ConfiguracionGoogle.cargar(ConfiguracionGoogle.ruta());
        if (configuracion == null) {
            throw new IllegalStateException("El inicio con Google no está configurado en este equipo (falta google_oauth.properties).");
        }
        cambiarTexto(texto, "Se ha abierto el navegador: elige tu cuenta de Google...");
        Consumer<URI> navegador = "http".equals(System.getProperty("cys.google.navegador"))
                ? InicioGoogle::seguirSinNavegador : InicioGoogle::abrirEnNavegador;
        CredencialGoogle credencial = new InicioGoogle(configuracion).iniciar(navegador);
        cambiarTexto(texto, "Cuenta de Google " + credencial.correo() + " comprobada. Entrando...");
        return credencial;
    }

    private static void cambiarTexto(JLabel etiqueta, String texto) {
        SwingUtilities.invokeLater(() -> etiqueta.setText(texto));
    }

    // La contraseña del almacén de confianza no es secreta: solo contiene el certificado PÚBLICO del servidor
    // (igual que el almacén cacerts de Java, cuya contraseña es "changeit"). Se puede cambiar con CYS_CLAVE_CONFIANZA.
    private static char[] claveConfianza() {
        String clave = System.getenv("CYS_CLAVE_CONFIANZA");
        return (clave == null || clave.isEmpty() ? "cys-confianza" : clave).toCharArray();
    }

    private static JDialog ventanaEspera(JLabel texto) {
        JProgressBar barra = new JProgressBar();
        barra.setIndeterminate(true);
        JPanel panel = new JPanel(new BorderLayout(0, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(14, 18, 10, 18));
        panel.add(texto, BorderLayout.NORTH);
        panel.add(barra, BorderLayout.CENTER);
        JDialog dialogo = new JDialog((JFrame) null, TITULO, true);
        dialogo.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
        dialogo.setLayout(new BorderLayout());
        dialogo.add(panel, BorderLayout.CENTER);
        return dialogo;
    }

    // ------------------------------------------------------------------ ventana principal

    private void abrirVentanaPrincipal(List<DetalleArchivo> archivos) {
        JPanel barra = new JPanel(new FlowLayout(FlowLayout.LEFT));
        botones.clear();
        anadirBoton(barra, "Cifrar archivo...", this::cifrar);
        anadirBoton(barra, "Descifrar...", this::descifrar);
        anadirBoton(barra, "Compartir...", this::compartir);
        anadirBoton(barra, "Cerrar sesión", this::cerrarSesion);

        String google = sesion.getCorreoGoogle() != null ? "  ·  protegido con Google (" + sesion.getCorreoGoogle() + ")" : "";
        ventana = new JFrame(TITULO + " - " + sesion.getUsuario() + google);
        ventana.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
        ventana.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                sesion.close();
                ventana.dispose();
                System.exit(0);
            }
        });
        ventana.add(barra, BorderLayout.NORTH);
        ventana.add(new JScrollPane(lista), BorderLayout.CENTER);
        ventana.add(estado, BorderLayout.SOUTH);
        ventana.setSize(820, 400);
        ventana.setLocationRelativeTo(null);
        ventana.setVisible(true);
        mostrarLista(archivos);
    }

    private void anadirBoton(JPanel barra, String texto, Runnable accion) {
        JButton boton = new JButton(texto);
        boton.addActionListener(e -> accion.run());
        barra.add(boton);
        botones.add(boton);
    }

    // Guardar un archivo protegido: se cifra con una clave AES nueva y se sube al servidor
    private void cifrar() {
        JFileChooser selector = new JFileChooser();
        selector.setDialogTitle("Elige el archivo que quieres proteger");
        if (selector.showOpenDialog(ventana) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        Path archivo = selector.getSelectedFile().toPath();
        enSegundoPlano("Cifrando y subiendo " + archivo.getFileName() + "...", () -> sesion.cifrar(archivo),
                nuevo -> mostrarLista(sesion.listar()));
    }

    // Abrir un archivo: se baja, se comprueba su firma, se descifra en la carpeta elegida y se abre
    private void descifrar() {
        DetalleArchivo elegido = lista.getSelectedValue();
        if (elegido == null) {
            JOptionPane.showMessageDialog(ventana, "Selecciona un archivo de la lista.");
            return;
        }
        JFileChooser selector = new JFileChooser();
        selector.setDialogTitle("Carpeta donde guardar \"" + elegido.nombre() + "\"");
        selector.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        if (selector.showSaveDialog(ventana) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        Path carpeta = selector.getSelectedFile().toPath();
        enSegundoPlano("Bajando y descifrando " + elegido.nombre() + "...", () -> sesion.descifrar(elegido, carpeta), this::abrir);
    }

    // 7.4: abrir automáticamente el archivo descifrado
    private void abrir(Path destino) {
        mostrarLista(sesion.listar());
        boolean puedeAbrir = !"false".equals(System.getProperty("cys.abrir"))
                && Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.OPEN);
        if (puedeAbrir) {
            try {
                Desktop.getDesktop().open(destino.toFile());
                return;
            } catch (Exception e) {
                // no hay programa para ese tipo de archivo: se avisa de dónde está
            }
        }
        JOptionPane.showMessageDialog(ventana, "Archivo guardado en:\n" + destino);
    }

    // Compartir: el archivo no se vuelve a cifrar, solo su clave AES con la clave pública del destinatario
    private void compartir() {
        DetalleArchivo elegido = lista.getSelectedValue();
        if (elegido == null) {
            JOptionPane.showMessageDialog(ventana, "Selecciona un archivo de la lista.");
            return;
        }
        String destinatario = JOptionPane.showInputDialog(ventana, "¿Con qué usuario quieres compartir \"" + elegido.nombre() + "\"?",
                "Compartir", JOptionPane.QUESTION_MESSAGE);
        if (destinatario == null || destinatario.isBlank()) {
            return;
        }
        String para = destinatario.trim();
        enSegundoPlano("Compartiendo " + elegido.nombre() + " con " + para + "...", () -> {
            sesion.compartir(elegido, para);
            return para;
        }, ok -> {
            mostrarLista(sesion.listar());
            JOptionPane.showMessageDialog(ventana, "\"" + elegido.nombre() + "\" compartido con " + para + ".\nLo verá la próxima vez que entre.");
        });
    }

    // Rellena la lista manteniendo seleccionado el archivo que lo estaba
    private void mostrarLista(List<DetalleArchivo> archivos) {
        DetalleArchivo seleccionado = lista.getSelectedValue();
        modelo.clear();
        archivos.forEach(modelo::addElement);
        for (int i = 0; seleccionado != null && i < modelo.size(); i++) {
            if (modelo.get(i).id().equals(seleccionado.id())) {
                lista.setSelectedIndex(i);
            }
        }
        estado.setText("Conectado a " + servidor + " como " + sesion.getUsuario() + "  ·  " + archivos.size()
                + (archivos.size() == 1 ? " archivo" : " archivos") + "  ·  doble clic para descifrar");
    }

    // 7.6 Cerrar sesión: se borran de memoria el token y las claves y se vuelve a la pantalla de acceso
    private void cerrarSesion() {
        String usuario = sesion.getUsuario();
        sesion.close();
        ventana.dispose();
        modelo.clear();
        pedirAcceso(usuario);
    }

    // ------------------------------------------------------------------ segundo plano y errores

    private <T> void enSegundoPlano(String texto, Tarea<T> tarea, Consumer<T> alTerminar) {
        ocupado(true, texto);
        new SwingWorker<T, Void>() {
            @Override
            protected T doInBackground() throws Exception {
                return tarea.ejecutar();
            }

            @Override
            protected void done() {
                ocupado(false, null);
                try {
                    alTerminar.accept(get());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } catch (ExecutionException e) {
                    tratarError(e.getCause());
                }
            }
        }.execute();
    }

    private void ocupado(boolean si, String texto) {
        botones.forEach(b -> b.setEnabled(!si));
        lista.setEnabled(!si);
        ventana.setCursor(Cursor.getPredefinedCursor(si ? Cursor.WAIT_CURSOR : Cursor.DEFAULT_CURSOR));
        if (texto != null) {
            estado.setText(texto);
        }
    }

    private void tratarError(Throwable e) {
        if (e instanceof ErrorServidor error && error.estado() == 401) {
            JOptionPane.showMessageDialog(ventana, "La sesión ha caducado. Vuelve a entrar.", TITULO, JOptionPane.WARNING_MESSAGE);
            cerrarSesion();
            return;
        }
        mostrarLista(sesion.listar());
        JOptionPane.showMessageDialog(ventana, mensajeDe(e, false), "No se ha podido completar", JOptionPane.ERROR_MESSAGE);
    }

    // Traduce una excepción a un mensaje que entienda cualquier usuario
    private String mensajeDe(Throwable e, boolean enAcceso) {
        if (e instanceof ErrorServidor error) {
            String m = error.getMessage();
            return switch (error.estado()) {
                case 401 -> m.contains("Google") ? m + "." : enAcceso ? "Usuario o contraseña incorrectos." : "La sesión ha caducado. Vuelve a entrar.";
                case 404 -> m.contains("usuario") ? "El usuario destinatario no existe." : "El archivo ya no está en el servidor.";
                case 409 -> m.contains("Google") ? m + "." : "Ese nombre de usuario ya existe. Elige otro.";
                case 413 -> "El archivo es demasiado grande para el servidor.";
                default -> m.isBlank() ? "El servidor ha respondido con un error (" + error.estado() + ")." : m + ".";
            };
        }
        if (e instanceof FirmaNoValidaException) {
            return e.getMessage();
        }
        if (e instanceof ContrasenaIncorrectaException) {
            return "No se ha podido descifrar tu clave privada: puede que se haya modificado en el servidor.";
        }
        if (e instanceof IllegalArgumentException || e instanceof IllegalStateException) {
            return e.getMessage();
        }
        // Primero se busca un fallo de certificado en TODA la cadena de causas: Java a veces lo envuelve en un
        // error de conexión, y entonces parecería que el servidor no está encendido
        String detalle = "\n\nDetalle: " + detalleTecnico(e);
        for (Throwable causa = e; causa != null; causa = causa.getCause()) {
            if (causa instanceof SSLException || causa instanceof java.security.cert.CertificateException) {
                return "No se puede establecer una conexión segura con " + servidor + ".\n"
                        + "El certificado del servidor no es el esperado: o no incluye esta dirección (genéralo con\n"
                        + "GenerarCertificado.bat \"dns:localhost,ip:127.0.0.1,ip:<IP del servidor>\") o el\n"
                        + "cliente_confianza.p12 de este equipo no es el del servidor." + detalle;
            }
        }
        for (Throwable causa = e; causa != null; causa = causa.getCause()) {
            if (causa instanceof ConnectException || causa instanceof UnknownHostException || causa instanceof HttpTimeoutException) {
                return "No se puede conectar con el servidor " + servidor + ".\nComprueba que está en marcha y que la dirección es correcta." + detalle;
            }
        }
        if (e instanceof java.io.IOException) {
            return "Se ha perdido la conexión con el servidor o no se ha podido leer o escribir el archivo." + detalle;
        }
        return "Ha ocurrido un error inesperado: " + e.getMessage();
    }

    // Causa más profunda de un error (clase y mensaje), para poder saber qué ha fallado de verdad
    private static String detalleTecnico(Throwable e) {
        Throwable raiz = e;
        while (raiz.getCause() != null && raiz.getCause() != raiz) {
            raiz = raiz.getCause();
        }
        return raiz.getClass().getSimpleName() + (raiz.getMessage() == null ? "" : ": " + raiz.getMessage());
    }
}
