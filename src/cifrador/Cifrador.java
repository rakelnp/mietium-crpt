/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cifrador;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
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
        String n = "ola mundo";
        Cipher e=Cipher.getInstance("RC4");
         KeyGenerator kg=KeyGenerator.getInstance("RC4");
         kg.init(128);
         SecretKey key = kg.generateKey();
      
         //para desincriptar basta mudar o modo de utilização
         e.init(Cipher.ENCRYPT_MODE,key);
         byte[] out= e.doFinal(n.getBytes());
      
         //array de bytes para string hexadecimal
         BigInteger x = new BigInteger(out);
         String t=x.toString(16);
      
     
         System.out.println("Mensagem:" +n);
         System.out.println("Mensagem cifrada:" +t);
    
    
}
}
