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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HttpsClient {

    /*
     * Endereço da ACT Serpro = https://act.serpro.gov.br
     * Porta da ACT Serpro = 318
     * OID da Politica da ACT Serpro = 2.16.76.1.6.2
     */
    private static final Logger logger = LoggerFactory.getLogger(HttpsClient.class);

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
            logger.info("Iniciando pedido de carimbo de tempo");
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
            logger.info("Creating a SSL Socket For {} on port {}", new Object[]{hostname, port});

            socket.startHandshake();
            logger.info("Handshaking Complete");
            socket.close();
            /*----------------------------------------------------------------------------------*/

            logger.info("Montando a requisicao para o carimbador de tempo");
            TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
//            reqgen.setReqPolicy(new ASN1ObjectIdentifier("1.3.6.1.4.1.13762.3"));
            timeStampRequestGenerator.setReqPolicy(new ASN1ObjectIdentifier("2.16.76.1.6.2"));
            TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(TSPAlgorithms.SHA256, new byte[20], BigInteger.valueOf(100));
            byte request[] = timeStampRequest.getEncoded();

            logger.info("Acessando o CSP {}", ocspUrl);

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
                logger.info("Response Code: ".concat(Integer.toString(con.getResponseCode())));
            }
            InputStream in = con.getInputStream();
            TimeStampResp resp = TimeStampResp.getInstance(new ASN1InputStream(in).readObject());
            TimeStampResponse response = new TimeStampResponse(resp);
            response.validate(timeStampRequest);

            logger.info("Status = {}", response.getStatusString());

            if (response.getFailInfo()
                    != null) {

                switch (response.getFailInfo().intValue()) {
                    case 0: {
                        logger.info("unrecognized or unsupported Algorithm Identifier");
                        return;
                    }

                    case 2: {
                        logger.info("transaction not permitted or supported");
                        return;
                    }

                    case 5: {
                        logger.info("the data submitted has the wrong format");
                        return;
                    }

                    case 14: {
                        logger.info("the TSA’s time source is not available");
                        return;
                    }

                    case 15: {
                        logger.info("the requested TSA policy is not supported by the TSA");
                        return;
                    }
                    case 16: {
                        logger.info("the requested extension is not supported by the TSA");
                        return;
                    }

                    case 17: {
                        logger.info("the additional information requested could not be understood or is not available");
                        return;
                    }

                    case 25: {
                        logger.info("the request cannot be handled due to system failure");
                        return;
                    }
                }
            }

            logger.info("Timestamp...............: {}", response.getTimeStampToken().getTimeStampInfo().getGenTime());
            logger.info("TSA.....................: {}", response.getTimeStampToken().getTimeStampInfo().getTsa());
            logger.info("Serial number...........: {}", response.getTimeStampToken().getTimeStampInfo().getSerialNumber());
            logger.info("Policy..................: {}", response.getTimeStampToken().getTimeStampInfo().getPolicy());
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private void print_https_cert(HttpsURLConnection con) {

        if (con != null) {

            try {
                logger.info("Response Code....: {}", con.getResponseCode());
                logger.info("Cipher Suite.....: {}", con.getCipherSuite());
                logger.info("\n");

                Certificate[] certs = con.getServerCertificates();
                for (Certificate cert : certs) {
                    logger.info("Cert Type..................: {}", cert.getType());
                    logger.info("Cert Hash Code.............: {}", cert.hashCode());
                    logger.info("Cert Public Key Algorithm..: {}", cert.getPublicKey().getAlgorithm());
                    logger.info("Cert Public Key Format.....: {}", cert.getPublicKey().getFormat());
                    logger.info("\n");
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

                logger.info("****** Content of the URL ********");
                BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream()));

                String input;

                while ((input = br.readLine()) != null) {
                    logger.info(input);
                }
                br.close();

            } catch (IOException e) {
                e.printStackTrace();
            }

        }

    }
}
