/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package br.gov.frameworkdemoiselle.timestamp.digest;

import java.io.OutputStream;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 *
 * @author 07721825741
 */
public interface DigestCalculator {

    /**
     * Return the algorithm identifier representing the digest implemented by
     * this calculator.
     *
     * @return algorithm id and parameters.
     */
    AlgorithmIdentifier getAlgorithmIdentifier();

    /**
     * Returns a stream that will accept data for the purpose of calculating a
     * digest. Use org.bouncycastle.util.io.TeeOutputStream if you want to
     * accumulate the data on the fly as well.
     *
     * @return an OutputStream
     */
    OutputStream getOutputStream();

    /**
     * Return the digest calculated on what has been written to the calculator's
     * output stream.
     *
     * @return a digest.
     */
    byte[] getDigest();
}
