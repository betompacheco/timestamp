package br.gov.frameworkdemoiselle.timestamp;

import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.util.Map;
import java.util.TimeZone;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

/**
 *
 * @author 07721825741
 */
public class Carimbo {

    private TimeStampToken timeStampToken = null;

    Carimbo(TimeStampToken timeStampToken) {
        this.timeStampToken = timeStampToken;
    }

    public String getPolitica() {
        return timeStampToken.getTimeStampInfo().getPolicy().toString();
    }

    public String getNumeroSerie() {
        return timeStampToken.getTimeStampInfo().getSerialNumber().toString();
    }

    public String getAlgoritmoDoHash() {
        return timeStampToken.getTimeStampInfo().getHashAlgorithm().getAlgorithm().toString();
    }

    public String getMessageImprintDigestBase64() {
        return Base64.toBase64String(timeStampToken.getTimeStampInfo().getMessageImprintDigest());
    }

    public String getMessageImprintDigestHex() {
        return Hex.toHexString(timeStampToken.getTimeStampInfo().getMessageImprintDigest()).toUpperCase();
    }

    public Store getCRLs() {
        return timeStampToken.getCRLs();
    }

    public Store getCertificados() {
        return timeStampToken.getCertificates();
    }

    public Map getAtributosAssinados() {
        return timeStampToken.getSignedAttributes().toHashtable();
    }

    public Map getatributosNaoAssinados() {
        return timeStampToken.getUnsignedAttributes().toHashtable();
    }

    /**
     * Retorna os dados da TSA (Time Stamping Authority)
     *
     * @return os atributos do certificado da TSA
     */
    public String getAutoridadeCarimboTempo() {
        return timeStampToken.getTimeStampInfo().getTsa().toString();
    }

    /**
     * Retorna o valor "nonce", ou retorna nulo se nao existir nenhum
     *
     * @return o valor "nonce"
     */
    public BigInteger getNonce() {
        return timeStampToken.getTimeStampInfo().getNonce();
    }

    public String getCarimbodeTempo() {
        SimpleDateFormat dateFormatGmt = new SimpleDateFormat("dd-MMM-yyyy HH:mm:ss:S z");
        dateFormatGmt.setTimeZone(TimeZone.getTimeZone("GMT"));
        return dateFormatGmt.format(timeStampToken.getTimeStampInfo().getGenTime());
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("Data e hora = ").append(this.getCarimbodeTempo()).append("\n");
        builder.append("Politica = ").append(this.getPolitica()).append("\n");
        builder.append("Serial = ").append(this.getNumeroSerie()).append("\n");
        builder.append("Certificado DN = ").append(this.getAutoridadeCarimboTempo()).append("\n");
        builder.append("Hash Algorithm = ").append(this.getAlgoritmoDoHash()).append("\n");
        builder.append("Message Imprint Digest (Hex) = ").append(this.getMessageImprintDigestHex()).append("\n");
        builder.append("Message Imprint Digest (Base64) = ").append(this.getMessageImprintDigestBase64()).append("\n");
        return builder.toString();
    }
}
