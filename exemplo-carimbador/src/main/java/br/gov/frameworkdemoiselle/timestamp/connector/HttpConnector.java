/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package br.gov.frameworkdemoiselle.timestamp.connector;

import java.io.InputStream;

/**
 *
 * @author 07721825741
 */
public class HttpConnector implements Connector {

    @Override
    public InputStream connect(byte[] content, String hostname, int port) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
}