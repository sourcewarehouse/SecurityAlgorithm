/*
 * SecurityAlgorithm
 * Copyright (c) 2011 - 2012, Alessio Chiapperini
 * Released under the GPL license
 * http://www.gnu.org/copyleft/gpl.html
 */
package it.spidernetlabs.security.crypto;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Classe che permette di criptare in MD5
 *
 * @author Alessio Chiapperini
 * @version 0.95
 */
public class MD5 {

    private String out = "";

    /**
     * Cripta la srtinga passata come parametro.
     *
     * @param password La string da criptare.
     * @return La stringa criptata.
     */
    public String encryptMD5(String password) {
        try {
            MessageDigest md;
            md = MessageDigest.getInstance("MD5");

            md.update(password.getBytes());
            byte[] mb = md.digest();
            for (int i = 0; i < mb.length; i++) {
                byte temp = mb[i];
                String s = Integer.toHexString(new Byte(temp));
                while (s.length() < 2) {
                    s = "0" + s;
                }
                s = s.substring(s.length() - 2);
                out += s;
            }
        } catch (NoSuchAlgorithmException e) {
            System.out.println("ERROR: " + e.getMessage());
        }
        return this.out;
    }

    /**
     * Cripta un file mediante l'algoritmo MD5.
     *
     * @param in Il file da criptare.
     * @param output Il file che conterrà il testo criptato.
     */
    public void encryptMD5(File in, File output) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            InputStream fis = new FileInputStream(in);

            int n = 0;
            byte[] buffer = new byte[8192];

            while (n != -1) {
                n = fis.read(buffer);
                if (n > 0) {
                    md.update(buffer, 0, n);
                }
            }

            byte[] mb = md.digest();
            for (int i = 0; i < mb.length; i++) {
                byte temp = mb[i];
                String s = Integer.toHexString(new Byte(temp));
                while (s.length() < 2) {
                    s = "0" + s;
                }
                s = s.substring(s.length() - 2);
                out += s;
            }

            FileWriter fw = new FileWriter(output);
            fw.write(out);
            fw.close();
        } catch (IOException ex) {
            Logger.getLogger(SHA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(SHA.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Cripta la stringa passata come parametro e la salva su un file.
     *
     * @param password La stringa da criptare.
     * @param output Il file che conterrà il testo criptato.
     */
    public void encryptMD5(String password, File output) {
        try {
            MessageDigest md;
            md = MessageDigest.getInstance("MD5");

            md.update(password.getBytes());
            byte[] mb = md.digest();
            for (int i = 0; i < mb.length; i++) {
                byte temp = mb[i];
                String s = Integer.toHexString(new Byte(temp));
                while (s.length() < 2) {
                    s = "0" + s;
                }
                s = s.substring(s.length() - 2);
                out += s;
                FileWriter fw = new FileWriter(output);
                fw.write(out);
                fw.close();
            }
        } catch (IOException ex) {
            Logger.getLogger(MD5.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("ERROR: " + e.getMessage());
        }
    }
}
