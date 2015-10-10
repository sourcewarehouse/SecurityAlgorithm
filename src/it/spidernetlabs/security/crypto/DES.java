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
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 * Classe che permette di criptare e decriptare mediante l'algoritmo DES.
 *
 * @author Alessio Chiapperini
 * @version 0.95
 */
public class DES {

    private Cipher ecipher;
    private Cipher dcipher;
    //8-byte Salt
    private final byte[] salt = {(byte) 0xA9, (byte) 0x9B, (byte) 0xC8, (byte) 0x32,
        (byte) 0x56, (byte) 0x35, (byte) 0xE3, (byte) 0x03};
    //Iteration count
    private final int iterationCount = 19;

    /**
     * Costruttore della classe. Genera la chiave e inizializza i cifrari.
     *
     * @param key Chiave con qui criptare.
     */
    public DES(String key) {
        try {
            //Create the key
            PBEKeySpec keySpec = new PBEKeySpec(key.toCharArray(), salt, iterationCount);
            SecretKey sKey = SecretKeyFactory.getInstance(
                    "PBEWithMD5AndDES").generateSecret(keySpec);
            ecipher = Cipher.getInstance(sKey.getAlgorithm());
            dcipher = Cipher.getInstance(sKey.getAlgorithm());

            //Prepare the parameter to the ciphers
            PBEParameterSpec paramSpec = new PBEParameterSpec(salt, iterationCount);

            //Create the ciphers
            ecipher.init(Cipher.ENCRYPT_MODE, sKey, paramSpec);
            dcipher.init(Cipher.DECRYPT_MODE, sKey, paramSpec);
        } catch (java.security.InvalidAlgorithmParameterException e) {
        } catch (java.security.spec.InvalidKeySpecException e) {
        } catch (javax.crypto.NoSuchPaddingException e) {
        } catch (java.security.NoSuchAlgorithmException e) {
        } catch (java.security.InvalidKeyException e) {
        }
    }

    /**
     * Critta la stringa passata come parametro.
     *
     * @param str Stringa da crittare.
     * @return la stringa criptata (Base64).
     */
    public String encrypt(String str) {
        try {
            //Encode the string into bytes using utf-8
            byte[] utf8 = str.getBytes("UTF8");

            //Encrypt
            byte[] enc = ecipher.doFinal(utf8);

            //Encode bytes to base64 to get a string
            return new sun.misc.BASE64Encoder().encode(enc);
        } catch (javax.crypto.BadPaddingException e) {
        } catch (IllegalBlockSizeException e) {
        } catch (UnsupportedEncodingException e) {
        } catch (java.io.IOException e) {
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
            byte[] encrypted = ecipher.doFinal(str.getBytes("UTF-8"));
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
            byte[] encrypted = ecipher.doFinal(str.getBytes());
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
     * @param str Stringa da decriptare.
     * @return la stringa originale.
     */
    public String decrypt(String str) {
        try {
            //Decode base64 to get bytes
            byte[] dec = new sun.misc.BASE64Decoder().decodeBuffer(str);

            //Decrypt
            byte[] utf8 = dcipher.doFinal(dec);

            //Decode using utf-8
            return new String(utf8, "UTF8");
        } catch (javax.crypto.BadPaddingException e) {
        } catch (IllegalBlockSizeException e) {
        } catch (UnsupportedEncodingException e) {
        } catch (java.io.IOException e) {
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
            String originalString = new String(dcipher.doFinal(this.hexToByte(str)), "UTF-8");

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
            String originalString = new String(dcipher.doFinal(this.hexToByte(str)), "UTF-8");

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
}
