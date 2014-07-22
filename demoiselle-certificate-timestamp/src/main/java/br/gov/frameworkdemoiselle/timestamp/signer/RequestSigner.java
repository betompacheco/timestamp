package br.gov.frameworkdemoiselle.timestamp.signer;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;

/**
 *
 * @author 07721825741
 */
public class RequestSigner {

    private final static Logger logger = Logger.getLogger(RequestSigner.class.getName());

    /**
     * Realiza a assinatura de uma requisicao de carimbo de tempo
     *
     * @param keystore
     * @param alias
     * @param password
     * @param request
     * @return A requisicao assinada
     */
    public byte[] signRequest(KeyStore keystore, String alias, char[] password, byte[] request) {

        logger.log(Level.INFO, "Efetuando a assinatura da requisicao");

        try {
            Security.addProvider(new BouncyCastleProvider());

            PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, password);
            X509Certificate signCert = (X509Certificate) keystore.getCertificate(alias);
            List<X509Certificate> certList = new ArrayList<>();
            certList.add(signCert);

            // setup the generator
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

            //TODO Obsoleto. use addSignerInfoGenerator
            SignerInfoGenerator signerInfoGenerator = new JcaSimpleSignerInfoGeneratorBuilder().build("SHA256withRSA", privateKey, signCert);
            generator.addSignerInfoGenerator(signerInfoGenerator);

            Store certStore = new JcaCertStore(certList);
            generator.addCertificates(certStore);

//            Store crlStore = new JcaCRLStore(crlList);
//            generator.addCRLs(crlStore);
            // Create the signed data object
            CMSTypedData data = new CMSProcessableByteArray(request);

            CMSSignedData signed = generator.generate(data, true);

            return signed.getEncoded();

        } catch (UnrecoverableKeyException | CMSException | NoSuchAlgorithmException | IOException | KeyStoreException ex) {
            logger.log(Level.INFO, ex.getMessage());
        } catch (OperatorCreationException | CertificateEncodingException ex) {
            logger.log(Level.INFO, ex.getMessage());
        }
        return null;
    }

}
