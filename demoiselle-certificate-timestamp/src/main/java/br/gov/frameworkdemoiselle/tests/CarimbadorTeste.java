package br.gov.frameworkdemoiselle.tests;

import br.gov.frameworkdemoiselle.certificate.criptography.Digest;
import br.gov.frameworkdemoiselle.certificate.criptography.DigestAlgorithmEnum;
import br.gov.frameworkdemoiselle.certificate.criptography.factory.DigestFactory;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CarimbadorTeste {

    private static final Logger logger = LoggerFactory.getLogger(CarimbadorTeste.class);

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

            logger.info("Timestamp...........: {}", response.getTimeStampToken().getTimeStampInfo().getGenTime());
            logger.info("TSA.................: {}", response.getTimeStampToken().getTimeStampInfo().getTsa());
            logger.info("Serial number.......: {}", response.getTimeStampToken().getTimeStampInfo().getSerialNumber());
            logger.info("Policy..............: {}", response.getTimeStampToken().getTimeStampInfo().getPolicy());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
