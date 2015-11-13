/*
* To change this license header, choose License Headers in Project Properties.
* To change this template file, choose Tools | Templates
* and open the template in the editor.
*/
package semana.pkg8;
import java.io.*;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import static javax.crypto.Cipher.DECRYPT_MODE;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
/**
 *
 * @author ASUS
 */
public class TServidor8 extends Thread{
    static final String CIPHER_MODE = "AES/CTR/NoPadding";
    static final String UNSAFE_PASS = "olamundo";
    
    private int ct;
    protected Socket s;
    DHParameterSpec dhS;
    
    TServidor8(Socket s, int c, DHParameterSpec dh) {
        this.ct = c;
        this.s=s;
        this.dhS = dh;
    }
    
    //static SecureRandom r = new SecureRandom();
    
    //static BigInteger P = new BigInteger("99494096650139337106186933977618513974146274831566768179581759037259788798151499814653951492724365471316253651463342255785311748602922458795201382445323499931625451272600173180136123245441204133515800495917242011863558721723303661523372572477211620144038809673692512025566673746993593384600667047373692203583");
    //static BigInteger G = new BigInteger("44157404837960328768872680677686802650999163226766694797650810379076416463147265401084491113667624054557335394761604876882446924929840681990106974314935015501571333024773172440352475358750668213444607353872754650805031912866692119819377041901642732455911509867728218394542745330014071040326856846990119719675");
    //static BigInteger X = new BigInteger(P.bitLength(), r);
    
    public void run() {
        
        try {
            ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
            ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());

            /**
             * acordo de chaves
             */
            // enviar G e P
            oos.writeObject(dhS.getG());
            oos.writeObject(dhS.getP());
            
            //gerar par de chaves a partir de P e G
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(dhS);
            
            KeyPair kp = kpg.generateKeyPair();
            Key Gx = kp.getPublic();
            Key x = kp.getPrivate();
            
            //Recebe Gy
            Key Gy = (Key) ois.readObject();
            //Envia Gx
            oos.writeObject(Gx);
            
            // inicializar acordo
            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(x);
            ka.doPhase(Gy, true);
            
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] rawbits = sha256.digest(ka.generateSecret());
            SecretKey key = new SecretKeySpec(rawbits,0,16,"AES");
            
            byte[] iv = (byte[]) ois.readObject(); 
            
            IvParameterSpec ivs = new IvParameterSpec(iv);
            
            Cipher c = Cipher.getInstance(CIPHER_MODE);
            c.init(DECRYPT_MODE,key,ivs);
            
            Mac m = Mac.getInstance("HmacSHA1");
            m.init(new SecretKeySpec(rawbits,16,16,"HmacSHA1"));
                    
            byte[] cipherText, clearText, mac;
            
            
                while (true) {
                    cipherText = (byte[])ois.readObject();
                    mac = (byte[]) ois.readObject();
                    if(!mac.equals(m.doFinal(cipherText))){
                        clearText = c.update(cipherText);
                        System.out.println(ct + " : " + new String(clearText));

                    }else{
                        System.out.println(ct+": Erro");
                    }
                }
                
           
            } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger(TServidor8.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}



