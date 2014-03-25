package br.gov.frameworkdemoiselle.timestamp.connector;

import br.gov.frameworkdemoiselle.timestamp.enumeration.ConnectionType;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ConnectorFactory {

    private final static Logger logger = Logger.getLogger(ConnectorFactory.class.getName());

    public static Connector buildConnector(ConnectionType connectionType) {

        switch (connectionType) {

            case HTTP: {
                logger.log(Level.INFO, "Retornando a conexao HTTP da fabrica");
                return new HttpConnector();
            }

            case SOCKET: {
                logger.log(Level.INFO, "Retornando a conexao Socket da fabrica");
                return new SocketConnector();
            }

            default: {
                logger.log(Level.INFO, "Retornando a conexao padrao da fábrica");
                return new SocketConnector();
            }
        }
    }

    private ConnectorFactory() {

    }
}
