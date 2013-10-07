package br.gov.frameworkdemoiselle;

import br.gov.frameworkdemoiselle.certificate.criptography.Digest;
import br.gov.frameworkdemoiselle.certificate.criptography.DigestAlgorithmEnum;
import br.gov.frameworkdemoiselle.certificate.criptography.factory.DigestFactory;
import java.io.*;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.tsp.TimeStampResp;

import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;

public class CarimbadorTeste {

    private final static Logger logger = Logger.getLogger(CarimbadorTeste.class.getName());

    public static void main(String[] args) {
        new CarimbadorTeste().carimbar();
    }

    private void carimbar() {

//        String ocspUrl = "http://timestamping.edelweb.fr/service/tsp";
        String ocspUrl = "http://services.globaltrustfinder.com/adss/tsa";

        OutputStream out = null;
        HttpURLConnection con = null;

        try {

            TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
//            timeStampRequestGenerator.setReqPolicy(new ASN1ObjectIdentifier("1.3.6.1.4.1.13762.3"));
            timeStampRequestGenerator.setReqPolicy(new ASN1ObjectIdentifier("1.2.3.4.5"));


            Digest digest = DigestFactory.getInstance().factoryDefault();
            digest.setAlgorithm(DigestAlgorithmEnum.SHA_1);
            byte[] hashedMessage = digest.digest("teste".getBytes());

            TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(TSPAlgorithms.SHA1, hashedMessage, BigInteger.valueOf(100));
            byte request[] = timeStampRequest.getEncoded();

            URL url = new URL(ocspUrl);
            con = (HttpURLConnection) url.openConnection();
            con.setDoOutput(true);
            con.setDoInput(true);
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-type", "application/timestamp-query");
            con.setRequestProperty("Content-length", String.valueOf(request.length));
            out = con.getOutputStream();
            out.write(request);
            out.flush();

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

            logger.log(Level.INFO, "Timestamp: {0}", response.getTimeStampToken().getTimeStampInfo().getGenTime());
            logger.log(Level.INFO, "TSA: {0}", response.getTimeStampToken().getTimeStampInfo().getTsa());
            logger.log(Level.INFO, "Serial number: {0}", response.getTimeStampToken().getTimeStampInfo().getSerialNumber());
            logger.log(Level.INFO, "Policy: {0}", response.getTimeStampToken().getTimeStampInfo().getPolicy());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
