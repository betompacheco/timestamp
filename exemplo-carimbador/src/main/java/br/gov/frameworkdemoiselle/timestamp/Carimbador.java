package br.gov.frameworkdemoiselle.timestamp;

import br.gov.frameworkdemoiselle.timestamp.digest.SHA256DigestCalculator;
import br.gov.frameworkdemoiselle.timestamp.messages.PKIStatusEnum;
import br.gov.frameworkdemoiselle.timestamp.signer.RequestSigner;
import br.gov.frameworkdemoiselle.timestamp.utils.Utils;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.tsp.TSPAlgorithms;
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
    Socket socket = null;
    OutputStream outputStream = null;
    InputStream inputStream = null;

    public static void main(String args[]) {
        new Carimbador().carimbar(null, null, null);
    }

    public void carimbar(byte[] content) {
    }

    public void carimbar(byte[] content, KeyStore ks, String a) {
        try {

            String hostname = "act.serpro.gov.br";
            int port = 318;

            Security.addProvider(new BouncyCastleProvider());

            logger.log(Level.INFO, "Iniciando pedido de carimbo de tempo");
            String CLIENT_PASSWORD = "G4bizinh4";

            String token = "name = TokenPro\nlibrary = /usr/lib/libeTPkcs11.so";
            // convert String into InputStream e instancia o Token
            InputStream is = new ByteArrayInputStream(token.getBytes());
            Provider provider = new sun.security.pkcs11.SunPKCS11(is);
            Security.addProvider(provider);

            KeyStore keystore = KeyStore.getInstance("PKCS11", "SunPKCS11-TokenPro");
            keystore.load(is, CLIENT_PASSWORD.toCharArray());
            String alias = keystore.aliases().nextElement();

            logger.log(Level.INFO, "Gerando o digest do conteudo");
            DigestCalculator digestCalculator = new SHA256DigestCalculator();
            digestCalculator.getOutputStream().write("serpro".getBytes());
            byte[] hashedMessage = digestCalculator.getDigest();
            logger.log(Level.INFO, Base64.toBase64String(hashedMessage));

            logger.log(Level.INFO, "Montando a requisicao para o carimbador de tempo");
            TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
            timeStampRequestGenerator.setReqPolicy(new ASN1ObjectIdentifier("2.16.76.1.6.2"));
            TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(TSPAlgorithms.SHA256, hashedMessage, BigInteger.valueOf(100));
            byte request[] = timeStampRequest.getEncoded();

            logger.info("Efetuando a  assinatura do conteudo");
            RequestSigner requestSigner = new RequestSigner();
            byte[] signed = requestSigner.assinar(keystore, alias, CLIENT_PASSWORD.toCharArray(), request);

            logger.info("Escreve o request assinado em disco");
            Utils.writeContent(signed, "request.tsq");


            logger.info("Envia a solicitacao para o servidor TSA");
            socket = new Socket(hostname, port);
            logger.log(Level.INFO, "Conectado? {0}", socket.isConnected());

            logger.info("Escrevendo no socket");
            outputStream = socket.getOutputStream();

            // INICIO DA ALTERACAO NA LEITURA DE DADOS
            logger.info("Escrevendo no socket");
            // A "direct TCP-based TSA message" consists of:length (32-bits), flag (8-bits), value
            outputStream.write(Utils.intToByteArray(1 + signed.length));
            outputStream.write(0x00);
            outputStream.write(signed);
            outputStream.flush();

            logger.info("Obtendo o response");
            inputStream = socket.getInputStream();

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
            System.out.println("Tamanho total = " + tamanho);

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
            byte[] carimbo = new byte[tamanho];
            inputStream.read(carimbo, 0, tamanho);

            logger.info("Escreve o response assinado em disco");
            Utils.writeContent(carimbo, "response.tsr");

            TimeStampResponse response = new TimeStampResponse(carimbo);
            System.out.println("PKIStatus = " + response.getStatus());

            switch (response.getStatus()) {
                case 0: {
                    logger.log(Level.INFO, PKIStatusEnum.granted.getMessage());
                }
                case 1: {
                    logger.log(Level.INFO, PKIStatusEnum.grantedWithMods.getMessage());
                }
                case 2: {
                    logger.log(Level.INFO, PKIStatusEnum.rejection.getMessage());
                }
                case 3: {
                    logger.log(Level.INFO, PKIStatusEnum.waiting.getMessage());
                }
                case 4: {
                    logger.log(Level.INFO, PKIStatusEnum.revocationWarning.getMessage());
                }
                case 5: {
                    logger.log(Level.INFO, PKIStatusEnum.revocationNotification.getMessage());
                }
            }

            response.validate(timeStampRequest);

            TimeStampToken timeStampToken = response.getTimeStampToken();
            if (timeStampToken != null) {
                logger.log(Level.INFO, "Data e hora = {0}", timeStampToken.getTimeStampInfo().getGenTime());
                logger.log(Level.INFO, "Serial = {0}", timeStampToken.getTimeStampInfo().getSerialNumber());
                logger.log(Level.INFO, "Certificado DN = {0}", timeStampToken.getTimeStampInfo().getTsa().toString());
                logger.log(Level.INFO, "Hash Algorithm = {0}", timeStampToken.getTimeStampInfo().getHashAlgorithm().getAlgorithm());
            } else {
                logger.log(Level.INFO, "O Token retornou nulo.");
            }
            // FIM DA ALTERACAO



        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                outputStream.close();
                inputStream.close();
                socket.close();
            } catch (IOException ex) {
                ex.printStackTrace();
            }

        }
    }

    /**
     * Valida um carimbo de tempo
     */
    public boolean validar() {
        return false;
    }
}
