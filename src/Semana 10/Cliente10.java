/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package semana.pkg9;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
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
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import static javax.crypto.Cipher.ENCRYPT_MODE;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
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
public class Cliente10 {
    static final String CIPHER_MODE = "AES/CTR/NoPadding";
    static final String UNSAFE_PASS = "olamundo";
            
    static public void main(String []args) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException {
      
       try {
           Socket s = new Socket("localhost",61919);
           ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
           ObjectInputStream ois = new ObjectInputStream(s.getInputStream());       
           /**
            * acordo de chaves
            */
           // Receber G e P
           BigInteger G=(BigInteger) ois.readObject();
           BigInteger P=(BigInteger) ois.readObject();
           DHParameterSpec dhS = new DHParameterSpec(P,G);
           //gerar par de chaves
           KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
           kpg.initialize(dhS);
           KeyPair kp = kpg.generateKeyPair();
           Key Gx = kp.getPublic();
           Key x = kp.getPrivate();
           
           BufferedReader teclado = new BufferedReader(new InputStreamReader(System.in));
           System.out.println("Chave privada do Cliente");
            String privPath=teclado.readLine();
            ObjectInputStream ficheiro1 = new ObjectInputStream(new FileInputStream(privPath));
            PrivateKey assig_priv=(PrivateKey) ficheiro1.readObject();
            
            System.out.println("Chave pública do Servidor");
            String pubPath=teclado.readLine();
            ObjectInputStream ficheiro2= new ObjectInputStream(new FileInputStream(pubPath));
            PublicKey assig_pub=(PublicKey) ficheiro2.readObject();
           
           
           // envia publica Gx
           oos.writeObject(Gx);
           // recebe publica Gy
           Key Gy = (Key) ois.readObject();
           //assinatura digital
            Signature sig=Signature.getInstance("SHA1withRSA");
           byte assinatura[]=(byte[]) ois.readObject();
           
           //verificar assinatura
            
            sig.initVerify(assig_pub);
            sig.update(Gx.getEncoded());
            sig.update(Gy.getEncoded());
            
           if(sig.verify(assinatura)){
               
               sig.initSign(assig_priv);
           //assinar Gy e Gx
            sig.update(Gx.getEncoded());
            sig.update(Gy.getEncoded());
               assinatura=sig.sign();
             oos.writeObject(assinatura);
               
               
           // inicializar acordo
           KeyAgreement ka = KeyAgreement.getInstance("DH");
           ka.init(x);
           ka.doPhase(Gy, true);
           MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
           byte[] rawbits = sha256.digest(ka.generateSecret());
           SecretKey key = new SecretKeySpec(rawbits,0,16,"AES");
           Cipher c = Cipher.getInstance(CIPHER_MODE);
           c.init(ENCRYPT_MODE, key);
           Mac m = Mac.getInstance("HmacSHA1");
           m.init(new SecretKeySpec(rawbits,16,16,"HmacSHA1"));
           // comunicar IV
           byte[] iv = c.getIV();
           oos.writeObject(iv);
           String test;
           BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
           byte[] cipherText, mac;
           while((test=stdIn.readLine())!=null) {
               
               cipherText = c.update(test.getBytes("UTF-8"));
               if(cipherText != null){
                   mac = m.doFinal(cipherText);
                   oos.writeObject(cipherText);
                   oos.writeObject(mac);
               }
           }
           
           oos.write(c.doFinal());// enviar final
           }
           else
               System.out.println("Erro: assinatura não verificada");
       } catch (IOException | ClassNotFoundException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
           Logger.getLogger(Cliente10.class.getName()).log(Level.SEVERE, null, ex);
       } catch (SignatureException ex) {
            Logger.getLogger(Cliente10.class.getName()).log(Level.SEVERE, null, ex);
        }
            
        
        
    }
}
