package br.gov.frameworkdemoiselle.timestamp.connector;

import java.io.InputStream;

/**
 *
 * @author 07721825741
 */
public interface IConnector {

    InputStream connect(byte[] conteudo);
}
