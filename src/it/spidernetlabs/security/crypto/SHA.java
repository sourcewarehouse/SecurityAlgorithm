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
 * Classe che permette di criptare mediante tutti gli algoritmi di SHA
 *
 * @author Alessio Chiapperini
 * @version 0.95
 */
public class SHA {

    private String out = "";

    /**
     * Cripta una stringa mediante l'algoritmo SHA256.
     *
     * @param password La stringa da criptare.
     * @return La stringa criptata.
     */
    public String encryptSHA256(String password) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");

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
        return out;
    }

    /**
     * Cripta un file mediante l'algoritmo SHA256.
     *
     * @param in Il file da criptare.
     * @param output Il file che conterrà il testo criptato.
     */
    public void encryptSHA256(File in, File output) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
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
    public void encryptSHA256(String password, File output) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");

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

            FileWriter fw = new FileWriter(output);
            fw.write(out);
            fw.close();
        } catch (IOException ex) {
            Logger.getLogger(SHA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("ERROR: " + e.getMessage());
        }
    }

    /**
     * Cripta una stringa mediante l'algoritmo SHA512
     *
     * @param password La Stringa da criptare.
     * @return La stringa criptata.
     */
    public String encryptSHA512(String password) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-512");

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
        return out;
    }

    /**
     * Cripta un file mediante l'algoritmo SHA512.
     *
     * @param in Il file da criptare.
     * @param output Il file che conterrà il testo criptato.
     */
    public void encryptSHA512(File in, File output) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
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
    public void encryptSHA512(String password, File output) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-512");

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

            FileWriter fw = new FileWriter(output);
            fw.write(out);
            fw.close();
        } catch (IOException ex) {
            Logger.getLogger(SHA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("ERROR: " + e.getMessage());
        }
    }

    /**
     * Cripta una stringa mediante l'algoritmo SHA384
     *
     * @param password La Stringa da criptare.
     * @return La stringa criptata.
     */
    public String encryptSHA384(String password) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-384");

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
        return out;
    }

    /**
     * Cripta un file mediante l'algoritmo SHA384.
     *
     * @param in Il file da criptare.
     * @param output Il file che conterrà il testo criptato.
     */
    public void encryptSHA384(File in, File output) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-384");
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
    public void encryptSHA384(String password, File output) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-384");

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

            FileWriter fw = new FileWriter(output);
            fw.write(out);
            fw.close();
        } catch (IOException ex) {
            Logger.getLogger(SHA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("ERROR: " + e.getMessage());
        }
    }

    /**
     * Cripta una stringa mediante l'algoritmo SHA1
     *
     * @param password La Stringa da criptare.
     * @return La stringa criptata.
     */
    public String encryptSHA1(String password) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-1");

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
        return out;
    }

    /**
     * Cripta un file mediante l'algoritmo SHA1.
     *
     * @param in Il file da criptare.
     * @param output Il file che conterrà il testo criptato.
     */
    public void encryptSHA1(File in, File output) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
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
    public void encryptSHA1(String password, File output) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-1");

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

            FileWriter fw = new FileWriter(output);
            fw.write(out);
            fw.close();
        } catch (IOException ex) {
            Logger.getLogger(SHA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("ERROR: " + e.getMessage());
        }
    }

    /**
     * Cripta una stringa mediante l'algoritmo SHA
     *
     * @param password La Stringa da criptare.
     * @return La stringa criptata.
     */
    public String encryptSHA(String password) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA");

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
        return out;
    }

    /**
     * Cripta un file mediante l'algoritmo SHA.
     *
     * @param in Il file da criptare.
     * @param output Il file che conterrà il testo criptato.
     */
    public void encryptSHA(File in, File output) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA");
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
    public void encryptSHA(String password, File output) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA");

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

            FileWriter fw = new FileWriter(output);
            fw.write(out);
            fw.close();
        } catch (IOException ex) {
            Logger.getLogger(SHA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("ERROR: " + e.getMessage());
        }
    }
}
