
package semana.pkg5;
import java.net.*;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.lang.Thread;
import java.net.Socket;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
/**
 *
 * @author ASUS
 */
public class Cliente {
    static final String CIPHER_MODE="AES/CTR/NoPadding";
    static final String UNSAFE_PASSWORD="PASSWORD!!!";
    static public void main(String []args) {
        try {
            Socket s = new Socket("localhost",61467);
            
            ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
            ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
          
           
            MessageDigest sha256=MessageDigest.getInstance("SHA-256");
            byte rawbits[]=sha256.digest(UNSAFE_PASSWORD.getBytes("UTF-8"));
             //encriptar a cifra
            Cipher e = Cipher.getInstance("CIPHER_MODE");
            SecretKey key =new SecretKeySpec(rawbits,0, 16,"AES");
            //IvParameterSpec iv=new IvParameterSpec(rawbits,16,16);
            e.init(Cipher.ENCRYPT_MODE, key);
            byte iv[]=e.getIV();
            oos.writeObject(iv);
            Mac m=Mac.getInstance("Hmac-SHA-1");
            m.init(new SecretKeySpec(rawbits,16,16,"Hmac-SHA-1"));
            
            String test;
            BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
            byte[] ciphertext, mac;
            while((test=stdIn.readLine())!=null) {
                //cifra e envia o criptograma 
                ciphertext = e.update(test.getBytes("UTF-8"));
                if(ciphertext!= null)
                {
                    mac = m.doFinal(ciphertext);
                oos.writeObject(ciphertext);
                oos.writeObject(mac);
            }}
            oos.write(e.doFinal());
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
}
