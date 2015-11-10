
package semana.pkg7;

import java.net.*;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.lang.Thread;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import static semana.pkg7.Cliente7.G;

/**
 *
 * @author ASUS
 */
class TServidor7 extends Thread {
    static final String CIPHER_MODE="AES/CTR/NoPadding";
    static SecureRandom r= new SecureRandom()  ;
    static final BigInteger P= new BigInteger ("99494096650139337106186933977618513974146274831566768179581759037259788798151499814653951492724365471316253651463342255785311748602922458795201382445323499931625451272600173180136123245441204133515800495917242011863558721723303661523372572477211620144038809673692512025566673746993593384600667047373692203583");
    static final BigInteger G= new BigInteger ("44157404837960328768872680677686802650999163226766694797650810379076416463147265401084491113667624054557335394761604876882446924929840681990106974314935015501571333024773172440352475358750668213444607353872754650805031912866692119819377041901642732455911509867728218394542745330014071040326856846990119719675");
    static final BigInteger x= new BigInteger (P.bitLength(),r);
    //contador/identificador
    private int ct;
    protected Socket s;
    
    TServidor7(Socket s, int c) {
        ct = c;
        this.s=s;
    }
    
    public void run() {
        
        System.out.println("<"+ct+">");
        try {
            ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
            ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
            
            //Acordo de Chaves
            //calcular a chave g^x e por fim o módulo de P
            BigInteger Gx=G.modPow(x,P);
            
            //receber Gy
            BigInteger Gy=(BigInteger) ois.readObject();
            //calcular g^x
            oos.writeObject(Gx);
            //calgular Gxy
            BigInteger Gyx= Gy.modPow(x,P);
            System.out.println("Gyx"+Gyx);
            MessageDigest sha256=MessageDigest.getInstance("SHA-256");
            byte rawbits[]=sha256.digest(Gyx.toByteArray());
            SecretKey key =new SecretKeySpec(rawbits,0, 16,"AES");
            
            byte ivbits[]=(byte[])ois.readObject();
            IvParameterSpec iv=new IvParameterSpec(ivbits);
            //encriptar a cifra
            
            Cipher e = Cipher.getInstance(CIPHER_MODE);
            e.init(Cipher.DECRYPT_MODE, key,iv);
            // byte ciphertext[],cleartext[];
            Mac m=Mac.getInstance("HmacSHA1");
            m.init(new SecretKeySpec(rawbits,16,16,"HmacSHA1"));
            
            String test;
            byte[] ciphertext,cleartext,mac;
            
            try {
                
                while (true) {
                    //test = (String) ois.readObject();
                    //System.out.println(ct + " : " + test);
                    ciphertext=(byte[]) ois.readObject();
                    mac=(byte[])ois.readObject();
                    if(!mac.equals(m.doFinal(ciphertext))){
                        cleartext=e.update(ciphertext);
                        System.out.println(ct + ":" + new String(cleartext, "UTF-8"));
                    }else
                    {
                        System.out.println(ct + ": EROO NA VERIFICAÇÃO!!!");
                    }
                }
            } catch (EOFException ex) {
                e.doFinal();
                //cleartext=e.doFinal();
                //System.out.println(ct + ":" + new String());
                System.out.println("["+ct + "]");
            } finally {
                if (ois!=null) ois.close();
                //if (oos!=null) oos.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

