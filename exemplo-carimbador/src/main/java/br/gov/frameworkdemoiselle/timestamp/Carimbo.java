package br.gov.frameworkdemoiselle.timestamp;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.TimeZone;
import java.util.logging.Level;
import org.bouncycastle.tsp.TimeStampToken;
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
        return Hex.toHexString(timeStampToken.getTimeStampInfo().getMessageImprintDigest());
    }

    /**
     * Retorna os dados da TSA (Time Stamping Authority)
     *
     * @return os atributos do certificado da TSA
     */
    public String getTSA() {
        return timeStampToken.getTimeStampInfo().getTsa().toString();
    }

    public String getCarimbo() {
        SimpleDateFormat dateFormatGmt = new SimpleDateFormat("dd-MMM-yyyy HH:mm:ss:S z");
        dateFormatGmt.setTimeZone(TimeZone.getTimeZone("GMT"));
        return dateFormatGmt.format(timeStampToken.getTimeStampInfo().getGenTime());
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("Data e hora = ").append(this.getCarimbo()).append("\n");
        builder.append("Politica = ").append(this.getPolitica()).append("\n");
        builder.append("Serial = ").append(this.getNumeroSerie()).append("\n");
        builder.append("Certificado DN = ").append(this.getTSA()).append("\n");
        builder.append("Hash Algorithm = ").append(this.getAlgoritmoDoHash()).append("\n");
        builder.append("Message Imprint Digest (Hex) = ").append(this.getMessageImprintDigestHex()).append("\n");
        builder.append("Message Imprint Digest (Base64) = ").append(this.getMessageImprintDigestBase64()).append("\n");
        return builder.toString();
    }
}
