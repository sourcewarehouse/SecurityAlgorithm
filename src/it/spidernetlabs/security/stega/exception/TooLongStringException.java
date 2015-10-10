/*
 * SecurityAlgorithm
 * Copyright (c) 2011 - 2012, Alessio Chiapperini
 * Released under the GPL license
 * http://www.gnu.org/copyleft/gpl.html
 */
package it.spidernetlabs.security.stega.exception;

/**
 * Classe eccezione per errori riguardante la lunghezza della stringa da
 * nascondere.
 *
 * L'eccezione viene scatenata quando si immette una stringa troppo lunga per
 * essere steganografata.
 *
 * @author Alessio Chiapperini
 * @version 0.95
 */
public class TooLongStringException extends Exception {

    public TooLongStringException(String message) {
        super(message);
    }

    public TooLongStringException() {
        this("La stringa è troppo lunga per essere criptata");
    }
}
