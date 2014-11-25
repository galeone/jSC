package jSC;
//GUI and unencrypted chat based on: http://www.cise.ufl.edu/~amyles/tutorials/tcpchat/

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.awt.event.KeyEvent;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.text.DefaultCaret;
import javax.xml.bind.DatatypeConverter;

import security.Ciphers;
import security.RSA;
import security.RSAKey;

public class CS implements Runnable {

	// Connect status constants
	private final static int NULL = 0;
	private final static int DISCONNECTED = 1;
	private final static int DISCONNECTING = 2;
	private final static int BEGIN_CONNECT = 3;
	private final static int CONNECTED = 4;
	private final static int WAITING_FOR_CONNECTIONS = 5;
	
	// Other constants
	private final static String statusMessages[] = {
			" Error! Could not connect!", " Disconnected", " Disconnecting...",
			" Connecting...", " Connected", " Waiting for connections..." };
	private final static CS tcpObj = new CS();

	private final static String END_CHAT_SESSION = new Character((char) 0).toString();

	// Connection state info
	private static String hostIP = "localhost";
	private static int port = 1234;
	private static int connectionStatus = DISCONNECTED;
	private static boolean isHost = true;
	private static String statusString = statusMessages[connectionStatus];
	private static StringBuffer toAppend = new StringBuffer("");
	private static StringBuffer toSend = new StringBuffer("");
	
	// Various GUI components and info
	private static JFrame mainFrame = null;
	private static JTextArea chatText = null;
	private static JTextField chatLine = null;
	private static JPanel statusBar = null;
	private static JLabel statusField = null;
	private static JTextField statusColor = null;

	private static JTextField ipField = null;
	private static JTextField portField = null;
	private static JRadioButton hostOption = null;
	private static JRadioButton guestOption = null;

	private static JButton connectButton = null;
	private static JButton disconnectButton = null;

	private static JTextArea logger = new JTextArea();

	// Logger components
	private static Integer eventCounter = 0;

	// TCP components
	private static ServerSocket hostServer = null;
	private static Socket socket = null;
	private static BufferedReader in = null;
	private static PrintWriter out = null;

	// RSA components (for session key exchange)
	private static RSA rsa = null;
	private static RSAKey clientKey = null;

	// AES components
	private static Cipher encryptor, decryptor;

	// Thread-safe way to append to the chat box
	private static void appendToChatBox(String s) {
		synchronized (toAppend) {
			toAppend.append(s);
		}
	}

	// The thread-safe way to change the GUI components while
	// changing state
	private static void changeStatus(int newConnectStatus, boolean noError) {
		// Change state if valid state
		if (newConnectStatus != NULL) {
			connectionStatus = newConnectStatus;
		}

		// If there is no error, display the appropriate status message
		if (noError) {
			statusString = statusMessages[connectionStatus];
		}
		// Otherwise, display error message
		else {
			statusString = statusMessages[NULL];
		}

		// Call the run() routine (Runnable interface) on the
		// error-handling and GUI-update thread
		SwingUtilities.invokeLater(tcpObj);
	}

	// Cleanup for disconnect
	private static void cleanUp() {
		try {
			if (hostServer != null) {
				hostServer.close();
				hostServer = null;
			}
		} catch (IOException e) {
			hostServer = null;
		}

		try {
			if (socket != null) {
				socket.close();
				socket = null;
			}
		} catch (IOException e) {
			socket = null;
		}

		try {
			if (in != null) {
				in.close();
				in = null;
			}
		} catch (IOException e) {
			in = null;
		}

		if (out != null) {
			out.close();
			out = null;
		}
	}

	// Initialize all the GUI components and display the frame
	private static void initGUI() {
		// Set up the status bar
		statusField = new JLabel();
		statusField.setText(statusMessages[DISCONNECTED]);
		statusColor = new JTextField(1);
		statusColor.setBackground(Color.red);
		statusColor.setEditable(false);
		statusBar = new JPanel(new BorderLayout());
		statusBar.add(statusColor, BorderLayout.WEST);
		statusBar.add(statusField, BorderLayout.CENTER);

		// Set up the options pane
		JPanel optionsPane = initOptionsPane();

		// Set up the chat pane
		JPanel chatPane = new JPanel(new BorderLayout());
		chatText = new JTextArea(10, 20);
		chatText.setLineWrap(true);
		chatText.setEditable(false);
		chatText.setForeground(Color.blue);
		JScrollPane chatTextPane = new JScrollPane(chatText,
				JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
				JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
		chatLine = new JTextField();
		chatLine.setEnabled(false);
		chatLine.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String s = chatLine.getText();
				if (!s.equals("")) {
					appendToChatBox("OUTGOING: " + s + "\n");
					chatLine.selectAll();
					// Send the string
					sendString(s);
				}
			}
		});
		chatPane.add(chatLine, BorderLayout.SOUTH);
		chatPane.add(chatTextPane, BorderLayout.CENTER);
		chatPane.setPreferredSize(new Dimension(200, 200));

		// Set up the main pane
		JPanel mainPane = new JPanel(new BorderLayout());
		mainPane.add(statusBar, BorderLayout.SOUTH);
		mainPane.add(optionsPane, BorderLayout.WEST);
		mainPane.add(chatPane, BorderLayout.CENTER);

		// Set up the main frame
		mainFrame = new JFrame("Java Secure Chat");
		mainFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		mainFrame.setContentPane(mainPane);
		mainFrame.setSize(mainFrame.getPreferredSize());
		mainFrame.setLocation(200, 200);
		mainFrame.pack();
		mainFrame.setVisible(true);

		rsa = new RSA();

		log("Generated public key: " + rsa.getPublicKey().toString());
		log("Generated private key: " + rsa.getPrivateKey().toString());

		JFrame loggerFrame = new JFrame();

		loggerFrame.setTitle("Logger");
		loggerFrame.setSize(500, 800);
		loggerFrame.setLayout(new GridLayout(1, 1));
		logger.setLineWrap(true);
		logger.setEditable(true);
		DefaultCaret caret = (DefaultCaret) logger.getCaret();
		caret.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);
		JScrollPane scroll = new JScrollPane(logger);
		scroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
		loggerFrame.add(scroll);
		loggerFrame.setVisible(true);
	}

	private static JPanel initOptionsPane() {
		JPanel pane = null;
		ActionListener buttonListener = null;

		// Create an options pane
		JPanel optionsPane = new JPanel(new GridLayout(4, 1));

		// IP address input
		pane = new JPanel(new FlowLayout(FlowLayout.RIGHT));
		pane.add(new JLabel("Host IP:"));
		ipField = new JTextField(10);
		ipField.setText(hostIP);
		ipField.setEnabled(false);
		ipField.addFocusListener(new FocusAdapter() {
			public void focusLost(FocusEvent e) {
				ipField.selectAll();
				// Should be editable only when disconnected
				if (connectionStatus != DISCONNECTED) {
					changeStatus(NULL, true);
				} else {
					hostIP = ipField.getText();
				}
			}
		});
		pane.add(ipField);
		optionsPane.add(pane);

		// Port input
		pane = new JPanel(new FlowLayout(FlowLayout.RIGHT));
		pane.add(new JLabel("Port:"));
		portField = new JTextField(10);
		portField.setEditable(true);
		portField.setText((new Integer(port)).toString());
		portField.addFocusListener(new FocusAdapter() {
			public void focusLost(FocusEvent e) {
				// should be editable only when disconnected
				if (connectionStatus != DISCONNECTED) {
					changeStatus(NULL, true);
				} else {
					int temp;
					try {
						temp = Integer.parseInt(portField.getText());
						port = temp;
					} catch (NumberFormatException nfe) {
						portField.setText((new Integer(port)).toString());
						mainFrame.repaint();
					}
				}
			}
		});
		pane.add(portField);
		optionsPane.add(pane);

		// Host/guest option
		buttonListener = new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (connectionStatus != DISCONNECTED) {
					changeStatus(NULL, true);
				} else {
					isHost = e.getActionCommand().equals("host");

					// Cannot supply host IP if host option is chosen
					if (isHost) {
						ipField.setEnabled(false);
						ipField.setText("localhost");
						hostIP = "localhost";
					} else {
						ipField.setEnabled(true);

					}
				}
			}
		};
		ButtonGroup bg = new ButtonGroup();
		hostOption = new JRadioButton("Host", true);
		hostOption.setMnemonic(KeyEvent.VK_H);
		hostOption.setActionCommand("host");
		hostOption.addActionListener(buttonListener);
		guestOption = new JRadioButton("Guest", false);
		guestOption.setMnemonic(KeyEvent.VK_G);
		guestOption.setActionCommand("guest");
		guestOption.addActionListener(buttonListener);
		bg.add(hostOption);
		bg.add(guestOption);
		pane = new JPanel(new GridLayout(1, 2));
		pane.add(hostOption);
		pane.add(guestOption);
		optionsPane.add(pane);

		// Connect/disconnect buttons
		JPanel buttonPane = new JPanel(new GridLayout(1, 2));
		buttonListener = new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				// Request a connection initiation
				if (e.getActionCommand().equals("connect")) {
					changeStatus(BEGIN_CONNECT, true);
				}
				// Disconnect
				else {
					changeStatus(DISCONNECTING, true);
				}
			}
		};
		connectButton = new JButton("Connect");
		connectButton.setMnemonic(KeyEvent.VK_C);
		connectButton.setActionCommand("connect");
		connectButton.addActionListener(buttonListener);
		connectButton.setEnabled(true);
		disconnectButton = new JButton("Disconnect");
		disconnectButton.setMnemonic(KeyEvent.VK_D);
		disconnectButton.setActionCommand("disconnect");
		disconnectButton.addActionListener(buttonListener);
		disconnectButton.setEnabled(false);
		buttonPane.add(connectButton);
		buttonPane.add(disconnectButton);
		optionsPane.add(buttonPane);

		return optionsPane;
	}

	// Log method, used to explain the exchanges between the two hosts
	public static void log(String message) {
		logger.append("[" + eventCounter + "] " + new Date() + ":\n" + message
				+ "\n");
		eventCounter++;
	}

	// The main procedure
	public static void main(String args[]) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException,
			InvalidAlgorithmParameterException {
		String s;

		initGUI();

		while (true) {
			try { // Poll every ~10 ms
				Thread.sleep(10);
			} catch (InterruptedException e) {
			}

			switch (connectionStatus) {
			case BEGIN_CONNECT:
				try {
					// Try to set up a server if host
					if (isHost) {
						hostServer = new ServerSocket(port);
						changeStatus(WAITING_FOR_CONNECTIONS, true);
						log("waiting for user public key");
						socket = hostServer.accept();
					}

					// If guest, try to connect to the server
					else {
						socket = new Socket(hostIP, port);
					}

					in = new BufferedReader(new InputStreamReader(
							socket.getInputStream()));
					out = new PrintWriter(socket.getOutputStream(), true);
					byte[] AESSeed;
					KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
					SecretKey secret = null;

					if (isHost) {
						String encodedPublickey = in.readLine();
						clientKey = RSAKey.parse(encodedPublickey);
						log("Received user public key: \n" + clientKey);
						log("Sending public key to the client");
						out.println(rsa.getPublicKey().toString());
						out.flush();
						log("Public key sent");

						log("Generating RSA encrypted seed for AES");
						secret = keyGenerator.generateKey();
						AESSeed = secret.getEncoded();
						String seedBase64Encoded = DatatypeConverter
								.printBase64Binary(AESSeed);
						log(seedBase64Encoded);
						String encryptedValue = RSA.encrypt(
								seedBase64Encoded.getBytes(), clientKey)
								.toString();
						log("Sending RSA encrypted seed for AES (Advanced Encryption Standard)");
						out.print(encryptedValue + "\n");
						out.flush();
						log("Seed sent");
					} else {
						log("Sending public key to the server");
						out.println(rsa.getPublicKey().toString());
						out.flush();
						log("Public key sent");
						log("waiting for server public key");
						String encodedPublickey = in.readLine();
						clientKey = RSAKey.parse(encodedPublickey);
						log("received server public key: \n" + clientKey);
						log("Waiting for RSA encrypted Seed for AES");
						String seedBase64Encoded = new String(
								rsa.decrypt(new BigInteger(in.readLine())));
						log(seedBase64Encoded);
						AESSeed = DatatypeConverter
								.parseBase64Binary(seedBase64Encoded);

						log("Received and decrypted AES seed");
						secret = new SecretKeySpec(AESSeed, "AES");
					}
					// use the first 16 byte of the server public modules as
					// init vector (since the mode is CBC)
					Ciphers ciphers = new Ciphers("AES/CBC/PKCS5PADDING",
							Arrays.copyOfRange(
									isHost ? rsa.getPublicKey().number.toByteArray()
										   : clientKey.number.toByteArray(), 0, 16));
					encryptor = ciphers.GetEncryptor(secret);
					decryptor = ciphers.GetDecryptor(secret);
					changeStatus(CONNECTED, true);
				}
				// If error, clean up and output an error message
				catch (IOException e) {
					cleanUp();
					changeStatus(DISCONNECTED, false);
				}
				break;

			case CONNECTED:
				try {
					// Send data
					if (toSend.length() != 0) {
						String encryptedValue = DatatypeConverter.printBase64Binary(
								encryptor.doFinal(toSend.toString().getBytes(Charset.forName("UTF-8"))));
						log("Sending base64(AES): " + encryptedValue);
						out.print(encryptedValue + "\n");
						out.flush();
						toSend.setLength(0);
						changeStatus(NULL, true);
					}

					// Receive data
					if (in.ready()) {
						s = in.readLine();
						if ((s != null) && (s.length() != 0)) {
							log("INCOMING base64(AES): " + s + "\n");
							s = new String(decryptor.doFinal(DatatypeConverter
									.parseBase64Binary(s))).trim();
							if (s.equals(END_CHAT_SESSION)) {
								changeStatus(DISCONNECTING, true);
								break;
							}
							appendToChatBox("INCOMING (converted): " + s + "\n");
							changeStatus(NULL, true);
						}
					}
				} catch (IOException e) {
					cleanUp();
					changeStatus(DISCONNECTED, false);
				}
				break;

			case DISCONNECTING:
				// Tell other chatter to disconnect as well
				out.print(END_CHAT_SESSION);
				out.flush();

				// Clean up (close all streams/sockets)
				cleanUp();
				changeStatus(DISCONNECTED, true);
				break;
			}
		}
	}

	// Add text to send-buffer
	private static void sendString(String s) {
		synchronized (toSend) {
			toSend.append(s + "\n");
		}
	}

	// Checks the current state and sets the enables/disables
	// accordingly
	public void run() {
		switch (connectionStatus) {
		case DISCONNECTED:
			connectButton.setEnabled(true);
			disconnectButton.setEnabled(false);
			ipField.setEnabled(true);
			portField.setEnabled(true);
			hostOption.setEnabled(true);
			guestOption.setEnabled(true);
			chatLine.setText("");
			chatLine.setEnabled(false);
			statusColor.setBackground(Color.red);
			break;

		case DISCONNECTING:
			connectButton.setEnabled(false);
			disconnectButton.setEnabled(false);
			ipField.setEnabled(false);
			portField.setEnabled(false);
			hostOption.setEnabled(false);
			guestOption.setEnabled(false);
			chatLine.setEnabled(false);
			statusColor.setBackground(Color.orange);
			break;

		case CONNECTED:
			connectButton.setEnabled(false);
			disconnectButton.setEnabled(true);
			ipField.setEnabled(false);
			portField.setEnabled(false);
			hostOption.setEnabled(false);
			guestOption.setEnabled(false);
			chatLine.setEnabled(true);
			statusColor.setBackground(Color.green);
			break;

		case WAITING_FOR_CONNECTIONS:
			connectButton.setEnabled(false);
			disconnectButton.setEnabled(true);
			ipField.setEnabled(false);
			portField.setEnabled(false);
			hostOption.setEnabled(false);
			guestOption.setEnabled(false);
			chatLine.setEnabled(true);
			statusColor.setBackground(Color.DARK_GRAY);
			break;

		case BEGIN_CONNECT:
			connectButton.setEnabled(false);
			disconnectButton.setEnabled(false);
			ipField.setEnabled(false);
			portField.setEnabled(false);
			hostOption.setEnabled(false);
			guestOption.setEnabled(false);
			chatLine.setEnabled(false);
			chatLine.grabFocus();
			statusColor.setBackground(Color.orange);
			break;
		}

		// Make sure that the button/text field states are consistent
		// with the internal states
		ipField.setText(hostIP);
		portField.setText((new Integer(port)).toString());
		hostOption.setSelected(isHost);
		guestOption.setSelected(!isHost);
		statusField.setText(statusString);
		chatText.append(toAppend.toString());
		toAppend.setLength(0);

		mainFrame.repaint();
	}
}