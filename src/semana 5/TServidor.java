
package semana.pkg5;
import java.net.*;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.lang.Thread;
import java.net.Socket;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import static semana.pkg5.Cliente.UNSAFE_PASSWORD;

/**
 *
 * @author ASUS
 */
class TServidor extends Thread {
    static final String CIPHER_MODE="AES/CTR/NoPadding";
    static final String UNSAFE_PASSWORD="PASSWORD!!!";
    //contador/identificador
    private int ct;
    protected Socket s;
    
    TServidor(Socket s, int c) {
        ct = c;
        this.s=s;
    }
    
    public void run() {
       
        System.out.println("<"+ct+">");
        try {
            ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
            ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
            MessageDigest sha256=MessageDigest.getInstance("SHA-256");
            byte rawbits[]=sha256.digest(UNSAFE_PASSWORD.getBytes("UTF-8"));
             //encriptar a cifra
            Cipher e = Cipher.getInstance("CIPHER_MODE");
            SecretKey key =new SecretKeySpec(rawbits,0, 16,"AES");
            byte ivbits[]=(byte[])ois.readObject();
            
            IvParameterSpec iv=new IvParameterSpec(ivbits);
            e.init(Cipher.DECRYPT_MODE, key,iv);
           // byte ciphertext[],cleartext[];
            Mac m=Mac.getInstance("Hmac-SHA-1");
            m.init(new SecretKeySpec(rawbits,16,16,"Hmac-SHA-1"));
                    
            String test;
           
                  byte[] ciphertext,cleartext,mac;  
                   // oos.writeObject(key);
            try {
                 //byte ciphertext[],cleartext[];
                while (true) {
                    //test = (String) ois.readObject();
                    //System.out.println(ct + " : " + test);
                    ciphertext=(byte[]) ois.readObject();
                    mac=(byte[])ois.readObject();
                    if(mac.equals(m.doFinal(ciphertext))){
                    cleartext=e.update(ciphertext);
                    System.out.println(ct + ":" + new String(cleartext, "UTF-8"));
                }else
                    {
                        System.out.println(ct + ": EROO NA VERIFICAÇÃO!!!");  
                    }}
            } catch (EOFException ex) {
                cleartext=e.doFinal();
                System.out.println(ct + ":" + new String());
                System.out.println("["+ct + "]");
            } finally {
                if (ois!=null) ois.close();
                if (oos!=null) oos.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
