/*
* To change this license header, choose License Headers in Project Properties.
* To change this template file, choose Tools | Templates
* and open the template in the editor.
*/
package semana.pkg9;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
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
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.Signature;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

/**
 *
 * @author ASUS
 */
public class TServidor10 extends Thread{
    static final String CIPHER_MODE = "AES/CTR/NoPadding";
    static final String UNSAFE_PASS = "olamundo";
    
    private int ct;
    protected Socket s;
    DHParameterSpec dhS;
    
    TServidor10(Socket s, int c, DHParameterSpec dh) {
        this.ct = c;
        this.s=s;
        this.dhS = dh;
    }
    
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
            
            byte[] Public_key=null;
            byte[] Private_key=null;       
            BufferedReader teclado = new BufferedReader(new InputStreamReader(System.in));
            
            System.out.println("Chave privada do servidor");
            String privPath=teclado.readLine();
            ObjectInputStream ficheiro1 = new ObjectInputStream(new FileInputStream(privPath));
            PrivateKey assig_priv=(PrivateKey) ficheiro1.readObject();
            
            System.out.println("Chave pública do cliente ");
            String pubPath=teclado.readLine();
            ObjectInputStream ficheiro2= new ObjectInputStream(new FileInputStream(pubPath));
            PublicKey assig_pub=(PublicKey) ficheiro2.readObject();

            //assinatura digital
            Signature sig=Signature.getInstance("SHA1withRSA");
            sig.initSign(assig_priv);
            //Recebe Gy
            Key Gy = (Key) ois.readObject();
            //Envia Gx
            oos.writeObject(Gx);
            
            //assinar Gy e Gx
            sig.update(Gy.getEncoded());
            sig.update(Gx.getEncoded());
            
          byte assinatura []= sig.sign();
           oos.writeObject(assinatura);
           
           byte assi_receive [];
            assi_receive = (byte[]) ois.readObject();
          
            //verificar assinatura
            
            sig.initVerify(assig_pub);
            sig.update(Gy.getEncoded());
            sig.update(Gx.getEncoded());
            
            if(sig.verify(assi_receive)){

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
            }
            else
                System.out.println("Erro:assinatura nao verificada");
            
        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger(TServidor10.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SignatureException ex) {
            Logger.getLogger(TServidor10.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
