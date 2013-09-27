package br.gov.frameworkdemoiselle.timestamp.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

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

    /**
     * Carrega o conteudo de um arquivo do disco
     *
     * @param arquivo Caminho do arquivo
     * @return Os bytes do arquivo
     */
    public static byte[] readContent(String arquivo) {
        byte[] result = null;
        try {
            File file = new File(arquivo);
            InputStream is = new FileInputStream(file);
            result = new byte[(int) file.length()];
            is.read(result);
            is.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
        return result;
    }

    /**
     * Escreve um conjunto de bytes em disco
     *
     * @param conteudo O conteudo a ser escrito em disco
     * @param arquivo O caminho e nome do arquivo
     */
    public static void writeContent(byte[] conteudo, String arquivo) {

        try {
            File file = new File(arquivo);
            OutputStream os = new FileOutputStream(file);
            os.write(conteudo);
            os.flush();
            os.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
}
