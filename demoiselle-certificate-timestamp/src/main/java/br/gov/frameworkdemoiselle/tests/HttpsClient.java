package br.gov.frameworkdemoiselle.tests;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;

public class HttpsClient {

    /*
     * Endereço da ACT Serpro = https://act.serpro.gov.br
     * Porta da ACT Serpro = 318
     * OID da Politica da ACT Serpro = 2.16.76.1.6.2
     */
    private final static Logger logger = Logger.getLogger(HttpsClient.class.getName());

    public static void main(String[] args) {
        new HttpsClient().stamp();
    }

    private void stamp() {

//        String ocspUrl = "http://ca.signfiles.com/tsa/get.aspx"; //Servidor OK
//        String ocspUrl = "http://timestamping.edelweb.fr/service/tsp"; //servidor OK
//        String ocspUrl = "https://clepsydre.edelweb.fr/dvcs/service-tsp"; //Servidor OK
        String ocspUrl = "https://act.serpro.gov.br:318";

        OutputStream out = null;
        HttpsURLConnection con = null;

        try {

//            String serverAddress = JOptionPane.showInputDialog("Enter IP Address of a machine that is\n" + "running the date service on port 9090:");
            logger.log(Level.INFO, "Iniciando pedido de carimbo de tempo");
            /*----------------------------------------------------------------------------------*/
            String CLIENT_PASSWORD = "G4bizinh4";
            String TRUSTSTORE_PASSWORD = "changeit";
            String hostname = "act.serpro.gov.br";
            int port = 318;

            String token = "name = Provedor\nlibrary = /usr/lib/libeTPkcs11.so";
            // convert String into InputStream e instancia o Token
            InputStream is = new ByteArrayInputStream(token.getBytes());
            Provider provider = new sun.security.pkcs11.SunPKCS11(is);
            Security.addProvider(provider);

            KeyStore clientStore = KeyStore.getInstance("PKCS11");
            clientStore.load(is, CLIENT_PASSWORD.toCharArray());
            KeyManagerFactory keyManagerfactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerfactory.init(clientStore, CLIENT_PASSWORD.toCharArray());

            //Set up a trust manager so we can recognize the server
            KeyStore trustStore = KeyStore.getInstance("JKS");
//            trustStore.load(new FileInputStream("truststore-clepsydre.jks"), TRUSTSTORE_PASSWORD.toCharArray());
            trustStore.load(new FileInputStream("truststore-serpro.jks"), TRUSTSTORE_PASSWORD.toCharArray());
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
            trustManagerFactory.init(trustStore);

            // load in the appropriate keystore and truststore for the server, get the X509KeyManager and X509TrustManager instances
            SSLContext sslContext = SSLContext.getInstance("TLS");

            // the final null means use the default secure random source
            sslContext.init(keyManagerfactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
//            sslContext.init(null, trustManagerFactory.getTrustManagers(), null);
//            sslContext.init(null, null, null);
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
            SSLSocket socket = (SSLSocket) sslSocketFactory.createSocket(hostname, port);
            logger.log(Level.INFO, "Creating a SSL Socket For {0} on port {1}", new Object[]{hostname, port});

            socket.startHandshake();
            logger.log(Level.INFO, "Handshaking Complete");
            socket.close();
            /*----------------------------------------------------------------------------------*/

            logger.log(Level.INFO, "Montando a requisicao para o carimbador de tempo");
            TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
//            reqgen.setReqPolicy(new ASN1ObjectIdentifier("1.3.6.1.4.1.13762.3"));
            timeStampRequestGenerator.setReqPolicy(new ASN1ObjectIdentifier("2.16.76.1.6.2"));
            TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(TSPAlgorithms.SHA256, new byte[20], BigInteger.valueOf(100));
            byte request[] = timeStampRequest.getEncoded();

            logger.log(Level.INFO, "Acessando o CSP {0}", ocspUrl);

            URL url = new URL(ocspUrl);

            if (ocspUrl.contains("https://")) {
                con = (HttpsURLConnection) url.openConnection();
                //parametriza um truststore personalizado
                con.setSSLSocketFactory(sslSocketFactory);
            } else {
//                con = (HttpURLConnection) url.openConnection();
            }

            con.setDoOutput(true);
            con.setDoInput(true);
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-type", "application/timestamp-query");
            con.setRequestProperty("Content-length", String.valueOf(request.length));
            out = con.getOutputStream();
            out.write(request);
            out.flush();

            //Imprime informacoes sobre a conexao SSL
//            print_https_cert(con);
            //Imprime o conteudo de retorno
//            print_content(con);
            if (con.getResponseCode() != HttpURLConnection.HTTP_OK) {
                throw new IOException("Received HTTP error: " + con.getResponseCode() + " - " + con.getResponseMessage());
            } else {
                logger.log(Level.INFO, "Response Code: ".concat(Integer.toString(con.getResponseCode())));
            }
            InputStream in = con.getInputStream();
            TimeStampResp resp = TimeStampResp.getInstance(new ASN1InputStream(in).readObject());
            TimeStampResponse response = new TimeStampResponse(resp);
            response.validate(timeStampRequest);

            logger.log(Level.INFO, "Status = {0}", response.getStatusString());

            if (response.getFailInfo()
                    != null) {

                switch (response.getFailInfo().intValue()) {
                    case 0: {
                        logger.log(Level.INFO, "unrecognized or unsupported Algorithm Identifier");
                        return;
                    }

                    case 2: {
                        logger.log(Level.INFO, "transaction not permitted or supported");
                        return;
                    }

                    case 5: {
                        logger.log(Level.INFO, "the data submitted has the wrong format");
                        return;
                    }

                    case 14: {
                        logger.log(Level.INFO, "the TSA’s time source is not available");
                        return;
                    }

                    case 15: {
                        logger.log(Level.INFO, "the requested TSA policy is not supported by the TSA");
                        return;
                    }
                    case 16: {
                        logger.log(Level.INFO, "the requested extension is not supported by the TSA");
                        return;
                    }

                    case 17: {
                        logger.log(Level.INFO, "the additional information requested could not be understood or is not available");
                        return;
                    }

                    case 25: {
                        logger.log(Level.INFO, "the request cannot be handled due to system failure");
                        return;
                    }
                }
            }

            logger.log(Level.INFO,
                    "Timestamp: {0}", response.getTimeStampToken().getTimeStampInfo().getGenTime());
            logger.log(Level.INFO,
                    "TSA: {0}", response.getTimeStampToken().getTimeStampInfo().getTsa());
            logger.log(Level.INFO,
                    "Serial number: {0}", response.getTimeStampToken().getTimeStampInfo().getSerialNumber());
            logger.log(Level.INFO,
                    "Policy: {0}", response.getTimeStampToken().getTimeStampInfo().getPolicy());
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private void print_https_cert(HttpsURLConnection con) {

        if (con != null) {

            try {
                logger.log(Level.INFO, "Response Code : {0}", con.getResponseCode());
                logger.log(Level.INFO, "Cipher Suite : {0}", con.getCipherSuite());
                logger.log(Level.INFO, "\n");

                Certificate[] certs = con.getServerCertificates();
                for (Certificate cert : certs) {
                    logger.log(Level.INFO, "Cert Type : {0}", cert.getType());
                    logger.log(Level.INFO, "Cert Hash Code : {0}", cert.hashCode());
                    logger.log(Level.INFO, "Cert Public Key Algorithm : {0}", cert.getPublicKey().getAlgorithm());
                    logger.log(Level.INFO, "Cert Public Key Format : {0}", cert.getPublicKey().getFormat());
                    logger.log(Level.INFO, "\n");
                }

            } catch (SSLPeerUnverifiedException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }

        }

    }

    private void print_content(HttpsURLConnection con) {
        if (con != null) {

            try {

                logger.log(Level.INFO, "****** Content of the URL ********");
                BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream()));

                String input;

                while ((input = br.readLine()) != null) {
                    logger.log(Level.INFO, input);
                }
                br.close();

            } catch (IOException e) {
                e.printStackTrace();
            }

        }

    }
}
