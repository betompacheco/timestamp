package br.gov.frameworkdemoiselle.timestamp;

import br.gov.frameworkdemoiselle.timestamp.connector.Connector;
import br.gov.frameworkdemoiselle.timestamp.connector.ConnectorFactory;
import br.gov.frameworkdemoiselle.timestamp.digest.DigestCalculator;
import br.gov.frameworkdemoiselle.timestamp.enumeration.ConnectionType;
import br.gov.frameworkdemoiselle.timestamp.exception.TimestampException;
import br.gov.frameworkdemoiselle.timestamp.enumeration.PKIFailureInfo;
import br.gov.frameworkdemoiselle.timestamp.enumeration.PKIStatus;
import br.gov.frameworkdemoiselle.timestamp.signer.RequestSigner;
import br.gov.frameworkdemoiselle.timestamp.utils.Utils;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.cms.CMSTimeStampedData;
import org.bouncycastle.tsp.cms.CMSTimeStampedDataGenerator;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;

/**
 *
 * @author 07721825741
 */
public class TimestampGenerator {

    private final static Logger logger = Logger.getLogger(TimestampGenerator.class.getName());
    private InputStream inputStream = null;
    private Timestamp timestamp;
    private TimeStampRequest timeStampRequest;
    private TimeStampResponse timeStampResponse;

    public static void main(String args[]) throws Exception {
        String CLIENT_PASSWORD = "G4bizinh4";
//        String CLIENT_PASSWORD = "Ju708410#";

        String token = "name = TokenPro\nlibrary = /usr/lib/libeTPkcs11.so";
        InputStream is = new ByteArrayInputStream(token.getBytes());
        Provider provider = new sun.security.pkcs11.SunPKCS11(is);
        Security.addProvider(provider);

        KeyStore keystore = KeyStore.getInstance("PKCS11", "SunPKCS11-TokenPro");
        keystore.load(is, CLIENT_PASSWORD.toCharArray());
        String alias = keystore.aliases().nextElement();

        TimestampGenerator carimbador = new TimestampGenerator();

//        byte[] dados = Utils.readContent("/home/07721825741/drivers.config");
//
//        byte[] pedido = carimbador.createRequest(dados, keystore, alias, new SHA256DigestCalculator());
//
//        logger.info("Escreve o request assinado em disco");
//        Utils.writeContent(pedido, "request.tsq");
//
//        byte[] resposta = carimbador.doTimestamp(pedido);
//
//        logger.info("Escreve o response assinado em disco");
//        Utils.writeContent(resposta, "response.tsr");

        carimbador.validate(Utils.readContent("response.tsr"), null);

        logger.log(Level.INFO, carimbador.getTimestamp().toString());
    }

    public byte[] createRequest(byte content) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    /**
     *
     * @param original
     * @param keystore
     * @param alias
     * @param digestCalculator
     * @return
     * @throws TimestampException
     * @throws IOException
     */
    public byte[] createRequest(byte[] original, KeyStore keystore, String alias, DigestCalculator digestCalculator) throws TimestampException, IOException {
        logger.log(Level.INFO, "Gerando o digest do conteudo");
        digestCalculator.getOutputStream().write(original);
        byte[] hashedMessage = digestCalculator.getDigest();
        logger.log(Level.INFO, Base64.toBase64String(hashedMessage));

        logger.log(Level.INFO, "Montando a requisicao para o carimbador de tempo");
        TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
        timeStampRequestGenerator.setReqPolicy(new ASN1ObjectIdentifier("2.16.76.1.6.2"));
        timeStampRequest = timeStampRequestGenerator.generate(TSPAlgorithms.SHA256, hashedMessage, BigInteger.valueOf(100));
        byte request[] = timeStampRequest.getEncoded();

        logger.info("Efetuando a  assinatura do conteudo");
        RequestSigner requestSigner = new RequestSigner();
        byte[] signedRequest = requestSigner.assinar(keystore, alias, null, request);

        return signedRequest;
    }

    /**
     *
     * @param request
     * @param connectionType
     * @return
     * @throws TimestampException
     */
    public byte[] doTimestamp(byte[] request, ConnectionType connectionType) throws TimestampException {
        try {
            logger.log(Level.INFO, "Iniciando pedido de carimbo de tempo");
            Connector connector = ConnectorFactory.buildConnector(connectionType);
            connector.setHostname("act.serpro.gov.br");
            connector.setPort(318);

            logger.info("Obtendo o response");
            inputStream = connector.connect(request);

            long tempo;
            // Valor do timeout da verificacao de dados disponiveis para leitura
            int timeOut = 3500;
            // Verificando se os 4 bytes iniciais estao disponiveis para leitura
            for (tempo = System.currentTimeMillis() + timeOut; inputStream.available() < 4 && System.currentTimeMillis() < tempo;) {
                try {
                    Thread.sleep(1L);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            // Lendo tamanho total
            byte[] tamanhoRetorno = new byte[4];
            inputStream.read(tamanhoRetorno, 0, 4);
            int tamanho = new BigInteger(tamanhoRetorno).intValue();

            // Verificando se os bytes na quantidade "tamanho" estao disponiveis
            if (System.currentTimeMillis() < tempo) {
                while (inputStream.available() < tamanho && System.currentTimeMillis() < tempo) {
                    try {
                        Thread.sleep(1L);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
                if (System.currentTimeMillis() >= tempo) {
                    System.out.println("Erro timeout ao receber dados");
                }
            } else {
                System.out.println("Erro timeout ao receber dados");
            }

            // Lendo flag
            byte[] flagRetorno = new byte[1];
            inputStream.read(flagRetorno, 0, 1);
            // tamanho total menos o tamanho da flag
            tamanho -= 1;

            // Lendo dados carimbo
            byte[] carimboRetorno = new byte[tamanho];
            inputStream.read(carimboRetorno, 0, tamanho);
            timeStampResponse = new TimeStampResponse(carimboRetorno);

            logger.log(Level.INFO, "PKIStatus = {0}", timeStampResponse.getStatus());

            switch (timeStampResponse.getStatus()) {
                case 0: {
                    logger.log(Level.INFO, PKIStatus.granted.getMessage());
                    break;
                }
                case 1: {
                    logger.log(Level.INFO, PKIStatus.grantedWithMods.getMessage());
                }
                case 2: {
                    logger.log(Level.INFO, PKIStatus.rejection.getMessage());
                    throw new TimestampException(PKIStatus.rejection.getMessage());
                }
                case 3: {
                    logger.log(Level.INFO, PKIStatus.waiting.getMessage());
                    throw new TimestampException(PKIStatus.waiting.getMessage());
                }
                case 4: {
                    logger.log(Level.INFO, PKIStatus.revocationWarning.getMessage());
                    throw new TimestampException(PKIStatus.revocationWarning.getMessage());
                }
                case 5: {
                    logger.log(Level.INFO, PKIStatus.revocationNotification.getMessage());
                    throw new TimestampException(PKIStatus.revocationNotification.getMessage());
                }
            }

            int failInfo = -1;

            if (timeStampResponse.getFailInfo() != null) {
                failInfo = Integer.parseInt(new String(timeStampResponse.getFailInfo().getBytes()));
            }

            logger.log(Level.INFO, "FailInfo = {0}", failInfo);

            switch (failInfo) {
                case 0:
                    logger.log(Level.INFO, PKIFailureInfo.badAlg.getMessage());
                    break;
                case 2:
                    logger.log(Level.INFO, PKIFailureInfo.badRequest.getMessage());
                    break;
                case 5:
                    logger.log(Level.INFO, PKIFailureInfo.badDataFormat.getMessage());
                    break;
                case 14:
                    logger.log(Level.INFO, PKIFailureInfo.timeNotAvailable.getMessage());
                    break;
                case 15:
                    logger.log(Level.INFO, PKIFailureInfo.unacceptedPolicy.getMessage());
                    break;
                case 16:
                    logger.log(Level.INFO, PKIFailureInfo.unacceptedExtension.getMessage());
                    break;
                case 17:
                    logger.log(Level.INFO, PKIFailureInfo.addInfoNotAvailable.getMessage());
                    break;
                case 25:
                    logger.log(Level.INFO, PKIFailureInfo.systemFailure.getMessage());
                    break;
            }

            timeStampResponse.validate(timeStampRequest);
            TimeStampToken timeStampToken = timeStampResponse.getTimeStampToken();
            timestamp = new Timestamp(timeStampToken);

            if (timeStampToken == null) {
                throw new TimestampException("O Token retornou nulo.");
            }

            connector.close();
            return carimboRetorno;

        } catch (Exception e) {
            throw new TimestampException(e.getMessage(), e.getCause());
        }
    }

    /**
     * Valida um carimbo de tempo
     *
     * @param response O response do servidor de carimbo de tempo
     * @param original
     * @return
     * @throws TSPException
     * @throws IOException
     * @throws CMSException
     * @throws OperatorCreationException
     * @throws CertificateException
     */
    public boolean validate(byte[] response, byte[] original) throws TSPException, IOException, CMSException, OperatorCreationException, CertificateException {

        boolean validado = true;

        Security.addProvider(new BouncyCastleProvider());
        TimeStampResponse tsr = new TimeStampResponse(response);
        TimeStampToken timeStampToken = tsr.getTimeStampToken();
        CMSSignedData s = timeStampToken.toCMSSignedData();

        int verified = 0;

        Store certStore = s.getCertificates();
        SignerInformationStore signers = s.getSignerInfos();
        Collection c = signers.getSigners();
        Iterator it = c.iterator();

        while (it.hasNext()) {
            SignerInformation signer = (SignerInformation) it.next();
            Collection certCollection = certStore.getMatches(signer.getSID());

            Iterator certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder) certIt.next();

            if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert))) {
                verified++;
            }
        }

        CMSTimeStampedDataGenerator tsdg = new CMSTimeStampedDataGenerator();
        CMSTimeStampedData tsd = tsdg.generate(timeStampToken);
        logger.log(Level.INFO, new String(tsd.getEncoded()));

        logger.log(Level.INFO, "verificados : {0}", verified);
        timestamp = new Timestamp(timeStampToken);
        return validado;
    }

    public Timestamp getTimestamp() {
        return timestamp;
    }
}
