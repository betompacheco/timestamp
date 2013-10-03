package br.gov.frameworkdemoiselle.timestamp;

import br.gov.frameworkdemoiselle.timestamp.connector.Connector;
import br.gov.frameworkdemoiselle.timestamp.connector.SocketConnector;
import br.gov.frameworkdemoiselle.timestamp.digest.DigestCalculator;
import br.gov.frameworkdemoiselle.timestamp.digest.SHA256DigestCalculator;
import br.gov.frameworkdemoiselle.timestamp.exception.TimestampException;
import br.gov.frameworkdemoiselle.timestamp.messages.PKIFailureInfoEnum;
import br.gov.frameworkdemoiselle.timestamp.messages.PKIStatusEnum;
import br.gov.frameworkdemoiselle.timestamp.signer.RequestSigner;
import br.gov.frameworkdemoiselle.timestamp.utils.Utils;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.encoders.Base64;

/**
 *
 * @author 07721825741
 */
public class Carimbador {

    private final static Logger logger = Logger.getLogger(Carimbador.class.getName());
    private InputStream inputStream = null;
    private Carimbo carimbo;
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

        byte[] dados = Utils.readContent("/home/07721825741/drivers.config");

        Carimbador carimbador = new Carimbador();

        byte[] pedido = carimbador.montaPedido(dados, keystore, alias, new SHA256DigestCalculator());

        logger.info("Escreve o request assinado em disco");
        Utils.writeContent(pedido, "request.tsq");

        byte[] resposta = carimbador.carimbar(pedido);

        logger.info("Escreve o response assinado em disco");
        Utils.writeContent(resposta, "response.tsr");

        logger.log(Level.INFO, carimbador.getCarimbo().toString());
    }

    public byte[] montaPedido(byte contet) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public byte[] montaPedido(byte[] content, KeyStore ks, String a, DigestCalculator digestCalculator) throws TimestampException, IOException {
        logger.log(Level.INFO, "Gerando o digest do conteudo");
        digestCalculator.getOutputStream().write(content);
        byte[] hashedMessage = digestCalculator.getDigest();
        logger.log(Level.INFO, Base64.toBase64String(hashedMessage));

        logger.log(Level.INFO, "Montando a requisicao para o carimbador de tempo");
        TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
        timeStampRequestGenerator.setReqPolicy(new ASN1ObjectIdentifier("2.16.76.1.6.2"));
        timeStampRequest = timeStampRequestGenerator.generate(TSPAlgorithms.SHA256, hashedMessage, BigInteger.valueOf(100));
        byte request[] = timeStampRequest.getEncoded();

        logger.info("Efetuando a  assinatura do conteudo");
        RequestSigner requestSigner = new RequestSigner();
        byte[] signedRequest = requestSigner.assinar(ks, a, null, request);

        return signedRequest;
    }

    /**
     *
     * @param request
     * @param ks
     * @param a
     * @param digestCalculator
     * @throws TimestampException
     */
    public byte[] carimbar(byte[] request) throws TimestampException {
        try {
            logger.log(Level.INFO, "Iniciando pedido de carimbo de tempo");
            Connector connector = new SocketConnector();
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

            int failInfo = -1;

            if (timeStampResponse.getFailInfo() != null) {
                failInfo = Integer.parseInt(new String(timeStampResponse.getFailInfo().getBytes()));
            }

            logger.log(Level.INFO, "FailInfo = {0}", failInfo);

            switch (failInfo) {
                case 0:
                    logger.log(Level.INFO, PKIFailureInfoEnum.badAlg.getMessage());
                    break;
                case 2:
                    logger.log(Level.INFO, PKIFailureInfoEnum.badRequest.getMessage());
                    break;
                case 5:
                    logger.log(Level.INFO, PKIFailureInfoEnum.badDataFormat.getMessage());
                    break;
                case 14:
                    logger.log(Level.INFO, PKIFailureInfoEnum.timeNotAvailable.getMessage());
                    break;
                case 15:
                    logger.log(Level.INFO, PKIFailureInfoEnum.unacceptedPolicy.getMessage());
                    break;
                case 16:
                    logger.log(Level.INFO, PKIFailureInfoEnum.unacceptedExtension.getMessage());
                    break;
                case 17:
                    logger.log(Level.INFO, PKIFailureInfoEnum.addInfoNotAvailable.getMessage());
                    break;
                case 25:
                    logger.log(Level.INFO, PKIFailureInfoEnum.systemFailure.getMessage());
                    break;
            }

            logger.log(Level.INFO, "PKIStatus = {0}", timeStampResponse.getStatus());

            switch (timeStampResponse.getStatus()) {
                case 0: {
                    logger.log(Level.INFO, PKIStatusEnum.granted.getMessage());
                    break;
                }
                case 1: {
                    logger.log(Level.INFO, PKIStatusEnum.grantedWithMods.getMessage());
                    throw new TimestampException(PKIStatusEnum.grantedWithMods.getMessage());
                }
                case 2: {
                    logger.log(Level.INFO, PKIStatusEnum.rejection.getMessage());
                    throw new TimestampException(PKIStatusEnum.rejection.getMessage());
                }
                case 3: {
                    logger.log(Level.INFO, PKIStatusEnum.waiting.getMessage());
                    throw new TimestampException(PKIStatusEnum.waiting.getMessage());
                }
                case 4: {
                    logger.log(Level.INFO, PKIStatusEnum.revocationWarning.getMessage());
                    throw new TimestampException(PKIStatusEnum.revocationWarning.getMessage());
                }
                case 5: {
                    logger.log(Level.INFO, PKIStatusEnum.revocationNotification.getMessage());
                    throw new TimestampException(PKIStatusEnum.revocationNotification.getMessage());
                }
            }
            timeStampResponse.validate(timeStampRequest);
            TimeStampToken timeStampToken = timeStampResponse.getTimeStampToken();
            carimbo = new Carimbo(timeStampToken);

            if (timeStampToken == null) {
                throw new TimestampException("O Token retornou nulo.");
            }

            connector.close();
            return carimboRetorno;

        } catch (Exception e) {
            throw new TimestampException(e.getMessage(), e.getCause());
        }
    }

    public Carimbo getCarimbo() {
        return carimbo;
    }

    /**
     * Valida um carimbo de tempo
     */
    public boolean validar() throws TSPException {
//        timeStampResponse.getTimeStampToken().get
        throw new UnsupportedOperationException("Nao implementado ainda.");
    }
}
