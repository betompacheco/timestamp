/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package br.gov.frameworkdemoiselle.timestamp;

import br.gov.frameworkdemoiselle.certificate.criptography.DigestAlgorithmEnum;
import br.gov.frameworkdemoiselle.timestamp.enumeration.ConnectionType;
import br.gov.frameworkdemoiselle.timestamp.utils.Utils;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import junit.framework.TestCase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author 07721825741
 */
public class TimestampGeneratorTest extends TestCase {

    private static final Logger logger = LoggerFactory.getLogger(TimestampGeneratorTest.class);

    byte[] original = null;
    byte[] response = null;

    public TimestampGeneratorTest(String testName) {
        super(testName);
    }

    @Override
    protected void setUp() throws Exception {
        String CLIENT_PASSWORD = "G4bizinh4";
//        String CLIENT_PASSWORD = "Ju708410#";

        TimestampGenerator timestampGen = new TimestampGenerator();

        original = Utils.readContent("/home/07721825741/texto.txt");

        String token = "name = TokenPro\nlibrary = /usr/lib/libeTPkcs11.so";
        InputStream is = new ByteArrayInputStream(token.getBytes());
        Provider provider = new sun.security.pkcs11.SunPKCS11(is);
        Security.addProvider(provider);

        KeyStore keystore = KeyStore.getInstance("PKCS11", "SunPKCS11-TokenPro");
        keystore.load(is, CLIENT_PASSWORD.toCharArray());
        String alias = keystore.aliases().nextElement();

        PrivateKey pk = (PrivateKey) keystore.getKey(alias, null);

        Certificate[] certificates = keystore.getCertificateChain(alias);

        byte[] pedido = timestampGen.createRequest(original, pk, certificates, DigestAlgorithmEnum.SHA_256);

        logger.info("Escreve o request assinado em disco");
        Utils.writeContent(pedido, "/home/07721825741/NetBeansProjects/timestamp/demoiselle-certificate-timestamp/request.tsq");

        byte[] resposta = timestampGen.doTimestamp(pedido, ConnectionType.SOCKET);

        logger.info("Escreve o response assinado em disco");
        Utils.writeContent(resposta, "/home/07721825741/NetBeansProjects/timestamp/demoiselle-certificate-timestamp/response.tsr");

        //Efetua a validacao do Token
        response = Utils.readContent("/home/07721825741/NetBeansProjects/timestamp/demoiselle-certificate-timestamp/response.tsr");

        timestampGen.validate(response, original);

        logger.info("Imprimindo os dados do TimeStamp Response");

        logger.info(timestampGen.getTimestamp().toString());
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * Test of validate method, of class TimestampGenerator.
     */
    public void testValidate_byteArr() throws Exception {
        System.out.println("validate");
        TimestampGenerator instance = new TimestampGenerator();
        instance.validate(response);
    }
}
