/*
 * SecurityAlgorithm
 * Copyright (c) 2011 - 2012, Alessio Chiapperini
 * Released under the GPL license
 * http://www.gnu.org/copyleft/gpl.html
 */
package it.spidernetlabs.security.stega;

import it.spidernetlabs.security.stega.exception.NotBMPDestinationFile;
import it.spidernetlabs.security.stega.exception.TooLongStringException;
import java.awt.Color;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import javax.imageio.ImageIO;

/**
 * Classe che permette di nascondere un testo in un' immagine
 *
 * @author Alessio
 * @version 0.95
 */
public class Steganography {

    /**
     * Apre il file a cui applicare la steganografia, dopo di che la applica e
     * salva l'immagine steganografata.
     *
     * Se la stringa da inseriere è troppo lunga scatena un'eccezione. Se
     * l'immagine non è un bitmap scatenza un'eccezione.
     *
     * @param openFile L'immagine a cui applicare la stegangrafia.
     * @param str La stringa da inserie nell'immagine.
     * @param destination
     * @throws IOException
     * @throws TooLongStringException
     * @throws NotBMPDestinationFile
     */
    public static void write(File openFile, String str, File destination) throws
            IOException, TooLongStringException, NotBMPDestinationFile {
        if (openFile.exists()) {
            BufferedImage img = ImageIO.read(openFile);
            String nameFile = destination.getPath();
            String ext = nameFile.substring(nameFile.length() - 3);

            if (str.length() > img.getWidth() * img.getHeight()) {
                throw new TooLongStringException();
            }

            if (!ext.equalsIgnoreCase("bmp")) {
                throw new NotBMPDestinationFile();
            }

            int w = 1;
            int h = 0;
            Color color = new Color(img.getRGB(0, 0));
            int r = color.getRed();
            int g = color.getGreen();
            int b = str.length();
            Color newColor = new Color(r, g, b);
            img.setRGB(0, 0, newColor.getRGB());

            for (int i = 0; i < str.length(); i++) {
                color = new Color(img.getRGB(w, h));
                r = color.getRed();
                g = color.getGreen();
                b = (int) str.charAt(i);
                newColor = new Color(r, g, b);
                img.setRGB(w, h, newColor.getRGB());
                w++;
                if (w >= img.getWidth()) {
                    w = 0;
                    h++;
                }
            }

            ImageIO.write(img, "bmp", destination);
        }
    }

    /**
     * Legge la stringa contenuta nell'immagine e la presenta all'utente.
     *
     * @param openFile L'immagine da aprire.
     * @return La stringa contenuta nell'immagine.
     * @throws IOException
     */
    public static String read(File openFile) throws IOException {
        if (openFile.exists()) {
            BufferedImage img = ImageIO.read(openFile);
            Color color = new Color(img.getRGB(0, 0));
            int leng = color.getBlue();
            int w = 1;
            int h = 0;
            char lett;
            String retval = "";

            for (int i = 0; i < leng; i++) {
                color = new Color(img.getRGB(w, h));
                lett = (char) color.getBlue();
                retval += lett;
                w++;
                if (w >= img.getWidth()) {
                    w = 0;
                    h++;
                }
            }
            return retval;
        }
        return "";
    }
}
