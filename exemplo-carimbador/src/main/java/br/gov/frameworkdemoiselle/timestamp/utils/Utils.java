package br.gov.frameworkdemoiselle.timestamp.utils;

/**
 *
 * @author 07721825741
 */
public class Utils {

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
