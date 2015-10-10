/*
 * SecurityAlgorithm
 * Copyright (c) 2011 - 2012, Alessio Chiapperini
 * Released under the GPL license
 * http://www.gnu.org/copyleft/gpl.html
 */
package it.spidernetlabs.security.crypto;

import java.io.*;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Classe che permette di criptare / decriptare mediante l'RSA.
 *
 * @author Alessio Chiapperini
 * @version 0.95
 */
public class RSA {

    private BigInteger privateKey;
    private BigInteger publicKey;
    private BigInteger modulus;

    /**
     * Costruttore della classe: Calcola modulo, chiave pubblica e privata.
     */
    public RSA() {
        BigInteger p = BigInteger.probablePrime(512, new SecureRandom());
        BigInteger q = BigInteger.probablePrime(512, new SecureRandom());

        modulus = p.multiply(q);
        BigInteger one = BigInteger.ONE;

        BigInteger pMin1 = p.subtract(one);
        BigInteger qMin1 = q.subtract(one);
        BigInteger fi = pMin1.multiply(qMin1);
        publicKey = new BigInteger("65537");
        privateKey = publicKey.modInverse(fi);
    }

    /**
     * Costruttore della classe: Calcola modulo e chiave privata.
     *
     * @param key La chiave pubblica.
     */
    public RSA(BigInteger key) {
        BigInteger p = BigInteger.probablePrime(512, new SecureRandom());
        BigInteger q = BigInteger.probablePrime(512, new SecureRandom());

        modulus = p.multiply(q);
        BigInteger one = BigInteger.ONE;

        BigInteger pMin1 = p.subtract(one);
        BigInteger qMin1 = q.subtract(one);
        BigInteger fi = pMin1.multiply(qMin1);
        this.publicKey = key;
        privateKey = publicKey.modInverse(fi);
    }

    /**
     * Calcola modulo, chiave pubblica e privata.
     *
     * @deprecated
     */
    public void prepare() {
        BigInteger p = BigInteger.probablePrime(512, new SecureRandom());
        BigInteger q = BigInteger.probablePrime(512, new SecureRandom());

        modulus = p.multiply(q);
        BigInteger one = BigInteger.ONE;

        BigInteger pMin1 = p.subtract(one);
        BigInteger qMin1 = q.subtract(one);
        BigInteger fi = pMin1.multiply(qMin1);
        publicKey = new BigInteger("65537");
        privateKey = publicKey.modInverse(fi);

    }

    /**
     * Cripta il numero passato.
     *
     * @param value Il numero da criptare.
     * @return Il numero criptato.
     */
    public BigInteger encrypt(BigInteger value) {
        return value.modPow(publicKey, modulus);
    }

    /**
     * Decripta il numero passato.
     *
     * @param crypto Il numero criptato.
     * @return Il numero originale.
     */
    public BigInteger decrypt(BigInteger crypto) {
        return crypto.modPow(privateKey, modulus);
    }

    /**
     * Stampa chiavi (pubblica e privata) e modulo.
     *
     * @return La stringa formata dalle chiavi e dal modulo.
     */
    public String printKey() {
        String s = "";
        s += "public key: " + publicKey + "\n";
        s += "private key: " + privateKey + "\n";
        s += "modulus: " + modulus;
        return s;
    }

    /**
     * Salva le chiavi e il modulo su file.
     */
    public void saveKey() {
        try {
            saveToFile("private.txt", privateKey);
            saveToFile("public.txt", publicKey);
            saveToFile("module.txt", modulus);
        } catch (IOException ex) {
            Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Metodo che permette il salvataggio di un file.
     *
     * @param fileName Il nome del file da salvare.
     * @param mod Il contenuto del file.
     * @throws IOException
     */
    private void saveToFile(String fileName, BigInteger mod) throws IOException {
        FileWriter fw = new FileWriter(fileName);
        fw.write(mod.toString());
        fw.close();
    }

    /**
     * Metodo che permette il salvataggio di un file.
     *
     * @param fileName Il nome del file da salvare.
     * @param mod Il contenuto del file.
     * @throws IOException
     * @deprecated
     */
    private void saveFile(String fileName, BigInteger mod) throws IOException {
        ObjectOutputStream oout = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fileName)));
        try {
            oout.writeObject(mod.toString());
        } catch (Exception ex) {
            throw new IOException("Errore inaspettato!", ex);
        } finally {
            oout.close();
        }
    }
}
