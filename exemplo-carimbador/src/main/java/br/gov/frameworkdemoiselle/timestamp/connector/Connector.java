package br.gov.frameworkdemoiselle.timestamp.connector;

import java.io.InputStream;

/**
 *
 * @author 07721825741
 */
public interface Connector {

    InputStream connect(byte[] content);

    void setHostname(String hostname);

    void SetPort(int port);
}
