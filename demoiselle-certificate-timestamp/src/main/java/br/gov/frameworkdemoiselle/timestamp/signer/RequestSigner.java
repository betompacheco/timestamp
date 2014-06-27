package br.gov.frameworkdemoiselle.timestamp.signer;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

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
            List<X509Certificate> certList = new ArrayList<X509Certificate>();
            certList.add(signCert);

//            BasicCertificate bc = new BasicCertificate(signCert);
//            List<String> crlList = bc.getCRLDistributionPoint();
            CertStore certsAndCrls = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList));

            // setup the generator
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

            //TODO Obsoleto. use addSignerInfoGenerator
            generator.addSigner(privateKey, signCert, CMSSignedDataGenerator.DIGEST_SHA256);
//            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(privateKey);
//            generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(contentSigner, signCert));

            //TODO Obsoleto. use addCertificates and addCRLs
            generator.addCertificatesAndCRLs(certsAndCrls);
//            Store certStore = new JcaCertStore(certList);
//            generator.addCertificates(certStore);
//
//            Store crlStore = new JcaCRLStore(crlList);
//            generator.addCRLs(crlStore);

            // Create the signed data object
            CMSProcessable data = new CMSProcessableByteArray(request);

            //TODO Obsoleto. use generate(CMSTypedData, boolean)
            CMSSignedData signed = generator.generate(data, true, keystore.getProvider());

            return signed.getEncoded();

        } catch (UnrecoverableKeyException | CMSException | NoSuchAlgorithmException | IOException | KeyStoreException | InvalidAlgorithmParameterException ex) {
            logger.log(Level.INFO, ex.getMessage());
        } catch (CertStoreException ex) {
            Logger.getLogger(RequestSigner.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

}
