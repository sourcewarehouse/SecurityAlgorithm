/*
 * SecurityAlgorithm
 * Copyright (c) 2011 - 2012, Alessio Chiapperini
 * Released under the GPL license
 * http://www.gnu.org/copyleft/gpl.html
 */
package it.spidernetlabs.security.crypto;

import java.io.*;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Classe che permette di criptare / decriptare mediante l'algoritmo AES.
 *
 * @author Alessio Chiapperini
 * @version 0.95
 */
public class AES {

    private Cipher encipher;
    private Cipher decipher;

    /**
     * Costruttore della classe: genera la chiave e inizializza i cifrari.
     */
    public AES() {
        try {
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(128);

            this.setupCrypto(kgen.generateKey());
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Construttore della classe.
     *
     * @param key La chiave con cui cifrare.
     */
    public AES(String key) {
        SecretKeySpec skey = new SecretKeySpec(getMD5(key), "AES");
        this.setupCrypto(skey);
    }

    /**
     * Inizializza i cifrari.
     *
     * @param key La chiave con cui cifrare.
     */
    private void setupCrypto(SecretKey key) {
        //Create an 8-byte initialization vector
        byte[] iv = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

        AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
        try {
            encipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            decipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            //CBC requires an initialization vector
            encipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
            decipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
        } catch (Exception ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Cripta la stringa passata come parametro.
     *
     * @param str La stringa da criptare
     * @return La stringa criptata codificata in Base64.
     */
    public String encrypt(String str) {
        try {
            byte[] encrypted = encipher.doFinal(str.getBytes("UTF-8"));
            return this.asHex(encrypted);
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * Cripta la stringa passata come parametro e la salva su un file.
     *
     * @param str La stringa da criptare.
     * @param output Il file che conterrà il testo criptato.
     */
    public void encrypt(String str, File output) {
        String out;
        try {
            byte[] encrypted = encipher.doFinal(str.getBytes("UTF-8"));
            out = this.asHex(encrypted);

            FileWriter fw = new FileWriter(output);
            fw.write(out);
            fw.close();
        } catch (IOException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Cripta un file e ne restituisce un'altro contenente la stringa criptata.
     *
     * @param input Il file da criptare.
     * @param output Il file che conterrà il testo criptato.
     */
    public void encrypt(File input, File output) {
        String out;
        try {
            String str = readFile(input);
            byte[] encrypted = encipher.doFinal(str.getBytes());
            out = this.asHex(encrypted);

            FileWriter fw = new FileWriter(output);
            fw.write(out);
            fw.close();
        } catch (IOException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Decripta la stringa passata come parametro.
     *
     * @param str La stringa da decriptare.
     * @return La stringa originale.
     */
    public String decrypt(String str) {
        try {
            String originalString = new String(decipher.doFinal(this.hexToByte(str)), "UTF-8");

            return originalString;
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * Decripta la stringa passata come parametro e salva la stringa originale
     * su un file.
     *
     * @param str La stringa da decriptare.
     * @param output Il File in cui salvare la stringa originale.
     */
    public void decrypt(String str, File output) {
        try {
            String originalString = new String(decipher.doFinal(this.hexToByte(str)), "UTF-8");

            FileWriter fw = new FileWriter(output);
            fw.write(originalString);
            fw.close();
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Decripta un file e ne restituisce un'altro contenente la stringa
     * originale.
     *
     * @param input Il file da decriptare.
     * @param output Il file contenente la stringa originale.
     */
    public void decrypt(File input, File output) {
        try {
            String str = readFile(input);
            String originalString = new String(decipher.doFinal(this.hexToByte(str)), "UTF-8");

            FileWriter fw = new FileWriter(output);
            fw.write(originalString);
            fw.close();
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Converte byte[] in una stringa
     *
     * @param buf bytes[] da convertire in una stringa esadecimale.
     * @return La stringa esadecimale generata.
     */
    private String asHex(byte buf[]) {
        StringBuffer strBuf = new StringBuffer(buf.length * 2);
        int i;

        for (i = 0; i < buf.length; i++) {
            if (((int) buf[i] & 0xff) < 0x10) {
                strBuf.append("0");
            }
            strBuf.append(Long.toString((int) buf[i] & 0xff, 16));
        }
        return strBuf.toString();
    }

    private byte[] hexToByte(String hexString) {
        int len = hexString.length();
        byte[] ba = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            ba[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    + Character.digit(hexString.charAt(i + 1), 16));
        }
        return ba;
    }

    /**
     * Legge un file e ritorna una stringa che ospita il contenuto del file.
     *
     * @param file Il file da leggere.
     * @return Una stringa che ospita il contenuto del file.
     * @throws IOException
     */
    private String readFile(File file) throws IOException {
        FileInputStream stream = new FileInputStream(file);
        try {
            FileChannel fc = stream.getChannel();
            MappedByteBuffer bb = fc.map(FileChannel.MapMode.READ_ONLY, 0, fc.size());
            return Charset.defaultCharset().decode(bb).toString();
        } finally {
            stream.close();
        }
    }

    /**
     * Ottiene l'hash MD5 della stringa passata come parametro.
     *
     * @param input La stringa da cui ottenere l'hash.
     * @return L'hash MD5 della stringa.
     */
    private static byte[] getMD5(String input) {
        try {
            byte[] bytesOfMessage = input.getBytes("UTF-8");
            MessageDigest md = MessageDigest.getInstance("MD5");
            return md.digest(bytesOfMessage);
        } catch (Exception e) {
            return null;
        }
    }
}