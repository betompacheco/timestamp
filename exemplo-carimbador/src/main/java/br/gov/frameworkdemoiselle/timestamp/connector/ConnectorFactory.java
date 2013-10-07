package br.gov.frameworkdemoiselle.timestamp.connector;

import br.gov.frameworkdemoiselle.timestamp.enumeration.ConnectionType;

/**
 *
 * @author 07721825741
 */
public class ConnectorFactory {

    public static Connector buildConnector(ConnectionType connectionType) {

        switch (connectionType) {

            case HTTP: {
                return new HttpConnector();
            }

            case SOCKET: {
                return new SocketConnector();
            }
            default: {
                return new SocketConnector();
            }
        }
    }
}
