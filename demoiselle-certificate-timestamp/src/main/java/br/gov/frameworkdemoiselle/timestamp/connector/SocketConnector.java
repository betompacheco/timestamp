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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author 07721825741
 */
public class SocketConnector implements Connector {

    private static final Logger logger = LoggerFactory.getLogger(SocketConnector.class);

    private String hostname = "";
    private int port;
    OutputStream out = null;
    Socket socket = null;

    @Override
    public InputStream connect(byte[] content) {
        try {
            logger.info("Envia a solicitacao para o servidor TSA");
            socket = new Socket(hostname, port);

            logger.info("Conectado? {}", socket.isConnected());

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
            logger.info(ex.getMessage());
        }

    }
}
