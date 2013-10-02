/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package br.gov.frameworkdemoiselle.timestamp.connector;

import br.gov.frameworkdemoiselle.timestamp.utils.Utils;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author 07721825741
 */
public class SocketConnector implements Connector {

    private final static Logger logger = Logger.getLogger(SocketConnector.class.getName());
    private String hostname = "";
    private int port;
    OutputStream out = null;
    Socket socket = null;

    @Override
    public InputStream connect(byte[] content) {
        try {
            logger.info("Envia a solicitacao para o servidor TSA");
            socket = new Socket(hostname, port);

            logger.log(Level.INFO, "Conectado? {0}", socket.isConnected());

            logger.info("Escrevendo no socket");
            // A "direct TCP-based TSA message" consists of:length (32-bits), flag (8-bits), value
            out = socket.getOutputStream();
            out.write(Utils.intToByteArray(1 + content.length));
            out.write(0x00);
            out.write(content);
            out.flush();

            logger.info("Obtendo o response");
            return socket.getInputStream();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
        }
        return null;
    }

    @Override
    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    @Override
    public void setPort(int port) {
        this.port = port;
    }

    @Override
    public void close() {
        try {
            socket.close();
            out.close();
        } catch (IOException ex) {
            Logger.getLogger(SocketConnector.class.getName()).log(Level.SEVERE, null, ex);
        }

    }
}
