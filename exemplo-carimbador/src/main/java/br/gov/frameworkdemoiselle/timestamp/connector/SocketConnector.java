/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package br.gov.frameworkdemoiselle.timestamp.connector;

import br.gov.frameworkdemoiselle.timestamp.Carimbador;
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

    @Override
    public InputStream connect(byte[] content, String hostname, int port) {
        try {

            logger.info("Envia a solicitacao para o servidor TSA");
            Socket socket = new Socket(hostname, port);

            logger.log(Level.INFO, "Conectado? {0}", socket.isConnected());

            logger.info("Escrevendo no socket");
            OutputStream out = socket.getOutputStream();

            // INICIO DA ALTERACAO NA LEITURA DE DADOS
            logger.info("Escrevendo no socket");
            // A "direct TCP-based TSA message" consists of:length (32-bits), flag (8-bits), value
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
}
