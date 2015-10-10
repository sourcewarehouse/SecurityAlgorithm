/*
 * SecurityAlgorithm
 * Copyright (c) 2011 - 2012, Alessio Chiapperini
 * Released under the GPL license
 * http://www.gnu.org/copyleft/gpl.html
 */
package it.spidernetlabs.security.stega.exception;

/**
 * Classe eccezione per errori riguardante il formato del file di destinazione.
 *
 * L'eccezione viene scatenata quando si immette un file di destinazione con
 * estensione diversa da bmp.
 *
 * @author Alessio Chiapperini
 * @version 0.95
 */
public class NotBMPDestinationFile extends Exception {

    public NotBMPDestinationFile(String message) {
        super(message);
    }

    public NotBMPDestinationFile() {
        this("Il file di destinazione non è un BMP");
    }
}
