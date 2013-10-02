/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package br.gov.frameworkdemoiselle.timestamp.signer;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;

/**
 *
 * @author 07721825741
 */
public class RequestSigner {

    public byte[] assinar(KeyStore ks, String alias, char[] password, byte[] conteudo) {
        try {
            PrivateKey key = (PrivateKey) ks.getKey(alias, password);
            X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
            List<X509Certificate> certs = new ArrayList<X509Certificate>();
            certs.add(cert);
            CertStore certsAndCrls = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certs));

            // setup the generator
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            generator.addSigner(key, cert, CMSSignedDataGenerator.DIGEST_SHA256);
            generator.addCertificatesAndCRLs(certsAndCrls);

            // Create the signed data object
            CMSProcessable data = new CMSProcessableByteArray(conteudo);
            CMSSignedData signed = generator.generate(data, true, ks.getProvider());

            return signed.getEncoded();

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
