package cifrador;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 *
 * @author ASUS
 */
public class Cifrador {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        //String n = "ola mundo";
        Cipher e = Cipher.getInstance("RC4");
        Cipher e1 = Cipher.getInstance("RC4");
        KeyGenerator kg = KeyGenerator.getInstance("RC4");
        kg.init(128);
        SecretKey key = kg.generateKey();

        //para desincriptar basta mudar o modo de utilização
        e.init(Cipher.ENCRYPT_MODE, key);
        e1.init(Cipher.DECRYPT_MODE, key);
        try {

            String nome = "teste.txt";
            FileReader arq = new FileReader(nome);
            BufferedReader lerArq = new BufferedReader(arq);
            //FileWriter ficheiro = new FileWriter(destino);
            //BufferedWriter escficheiro = new BufferedWriter(ficheiro);
            String linha;
            linha = lerArq.readLine(); // lê da segunda até a última linha 
            // a variável "linha" recebe o valor "null" quando o processo
            // de repetição atingir o fim do ficheiro de texto 
            while (linha != null) {
                System.out.printf("\nMensagem original: %s\n", linha);
                byte[] out = e.doFinal(linha.getBytes());

                System.out.println("Mensagem cifrada:" + new String(out));
                byte[] out2 = e1.doFinal(out);
                System.out.println("Mensagem decifrada:" + new String(out2));

                linha = lerArq.readLine(); // lê da segunda até a última linha 
            }
            arq.close();
            //ficheiro.close();
        } catch (IOException ex) {
            Logger.getLogger(Cifrador.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
