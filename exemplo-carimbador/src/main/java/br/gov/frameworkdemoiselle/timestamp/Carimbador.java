package br.gov.frameworkdemoiselle.timestamp;

import br.gov.frameworkdemoiselle.timestamp.digest.SHA256DigestCalculator;
import br.gov.frameworkdemoiselle.timestamp.signer.RequestSigner;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
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
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.encoders.Base64;

/**
 *
 * @author 07721825741
 */
public class Carimbador {

    private final static Logger logger = Logger.getLogger(Carimbador.class.getName());

    public static void main(String args[]) {
        new Carimbador().carimbar();
    }

    public void carimbar() {
        try {
            Security.addProvider(new BouncyCastleProvider());

            logger.log(Level.INFO, "Iniciando pedido de carimbo de tempo");
            String CLIENT_PASSWORD = "G4bizinh4";

            String hostname = "act.serpro.gov.br";
            int port = 318;

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
            RequestSigner assinador = new RequestSigner();
            byte[] signed = assinador.assinar(keystore, alias, CLIENT_PASSWORD.toCharArray(), request);

            logger.info("Escreve o request assinado em disco");
            OutputStream fos = new FileOutputStream(new File("request.tsq"));
            fos.write(signed);
            fos.flush();
            fos.close();

            logger.info("Envia a solicitacao para o servidor TSA");
            Socket socket = new Socket(hostname, port);
            logger.log(Level.INFO, "Conectado? {0}", socket.isConnected());

            logger.info("Escrevendo no socket");
            OutputStream out = socket.getOutputStream();

            // INICIO DA ALTERACAO NA LEITURA DE DADOS
            logger.info("Escrevendo no socket");
            // A "direct TCP-based TSA message" consists of:length (32-bits), flag (8-bits), value
            out.write(intToByteArray(1 + signed.length));
            out.write(0x00);
            out.write(signed);
            out.flush();

            logger.info("Obtendo o response");
            InputStream in = socket.getInputStream();

            long tempo;
            // Valor do timeout da verificacao de dados disponiveis para leitura
            int timeOut = 3500;
            // Verificando se os 4 bytes iniciais estao disponiveis para leitura
            for (tempo = System.currentTimeMillis() + timeOut; in.available() < 4 && System.currentTimeMillis() < tempo;) {
                try {
                    Thread.sleep(1L);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            // Lendo tamanho total
            byte[] tamanhoRetorno = new byte[4];
            in.read(tamanhoRetorno, 0, 4);
            int tamanho = new BigInteger(tamanhoRetorno).intValue();
            System.out.println("Tamanho total = " + tamanho);

            // Verificando se os bytes na quantidade "tamanho" estao disponiveis
            if (System.currentTimeMillis() < tempo) {
                while (in.available() < tamanho && System.currentTimeMillis() < tempo) {
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
            in.read(flagRetorno, 0, 1);
            // tamanho total menos o tamanho da flag
            tamanho -= 1;

            // Lendo dados carimbo
            byte[] carimboBytes = new byte[tamanho];
            in.read(carimboBytes, 0, tamanho);



            logger.info("Escreve o response assinado em disco");
            OutputStream fosresp = new FileOutputStream(new File("response.tsr"));
            fosresp.write(carimboBytes);
            fosresp.flush();
            fosresp.close();

            TimeStampResponse response = new TimeStampResponse(carimboBytes);
            System.out.println("PKIStatus = " + response.getStatus());
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

            out.close();
            in.close();
            socket.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Valida um carimbo de tempo
     */
    public boolean validar() {
        return false;
    }

    /**
     * Efetua a conversao para Big Endian de acordo com a especificacao RFC 3161
     *
     * @param valor
     * @return
     */
    public static byte[] intToByteArray(int valor) {
        byte buffer[] = new byte[4];

        // PROTOCOLO RFC 3161 - formato big-endian da JVM
        buffer[0] = (byte) (valor >> 24 & 0xff);
        buffer[1] = (byte) (valor >> 16 & 0xff);
        buffer[2] = (byte) (valor >> 8 & 0xff);
        buffer[3] = (byte) (valor & 0xff);

        return buffer;
    }
}
