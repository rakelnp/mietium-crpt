
package semana12;

import java.io.BufferedReader;
import java.io.File;
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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
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

/**
 *
 * @author ASUS
 */
public class Cliente12 {
    static final String CIPHER_MODE = "AES/CTR/NoPadding";
    static final String UNSAFE_PASS = "olamundo";
            
    static public void main(String []args) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, CertificateException {
      
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
           
           
           KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
           kpg.initialize(dhS);
           KeyPair kp = kpg.generateKeyPair();
           Key Gx = kp.getPublic();
           Key x = kp.getPrivate();
           
           CertificateFactory factory= CertificateFactory.getInstance("X.509");
           Certificate caCert = factory.generateCertificate(new FileInputStream("CA.cer"));
           
           FileInputStream fisP12 = new FileInputStream(new File("Cliente.p12"));
           KeyStore ksCert = KeyStore.getInstance("PKCS12");
           ksCert.load(fisP12, "1234".toCharArray());
           
           //chave privada
           PrivateKey sigprivkey = (PrivateKey) ksCert.getKey("Cliente1", "1234".toCharArray());
                     
           //receber o certificado
           CertPath servidorCertPath =(CertPath)ois.readObject();
           //receber chave publica para fazer a verificaçao
           X509Certificate servidorCert = (X509Certificate) servidorCertPath.getCertificates().get(0);
           PublicKey servidorPubKey = servidorCert.getPublicKey();
          
                      //certificado
           Certificate[] certArray = ksCert.getCertificateChain("Cliente1");
           CertificateFactory certFactory = CertificateFactory.getInstance("X.509");  
           CertPath certPath = certFactory.generateCertPath(Arrays.asList(certArray));
           
           CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
                // TrustAnchor representa os pressupostos de confiança que se aceita como válidos
                // (neste caso, unicamente a CA que emitiu os certificados)
                TrustAnchor anchor = new TrustAnchor((X509Certificate) caCert, null);
                // Podemos também configurar o próprio processo de validação
                // (e.g. requerer a presença de determinada extensão).
                PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
                // ...no nosso caso, vamos simplesmente desactivar a verificação das CRLs
                params.setRevocationEnabled(false);
                // Finalmente a validação propriamente dita...
                 try {
                     CertPathValidatorResult cpvResult = cpv.validate ((CertPath)certPath, params);
                     System.out.println("SE CHEGOU AQUI, TUDO DEVE TER CORRIDO BEM!!!");
                 } catch (InvalidAlgorithmParameterException iape) {
                     System.err.println("Erro de validação: " + iape);
                     System.exit(1);
                 } catch (CertPathValidatorException cpve) {
                     System.err.println("FALHA NA VALIDAÇÃO: " + cpve);
                     System.err.println("Posição do certificado causador do erro: "
                             + cpve.getIndex());
                 }
           
           //enviar certificado
           oos.writeObject(certPath);
           // envia publica Gx
           oos.writeObject(Gx);
           // recebe publica Gy
           Key Gy = (Key) ois.readObject();
           //assinatura digital
            Signature sig=Signature.getInstance("SHA1withRSA");
           byte assinatura[]=(byte[]) ois.readObject();
           
           //verificar assinatura
            
            sig.initVerify(servidorPubKey);
            sig.update(Gx.getEncoded());
            sig.update(Gy.getEncoded());
            
           if(sig.verify(assinatura)){
               
              sig.initSign(sigprivkey);
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
           Logger.getLogger(Cliente12.class.getName()).log(Level.SEVERE, null, ex);
       } catch (SignatureException ex) {
            Logger.getLogger(Cliente12.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyStoreException ex) {
            Logger.getLogger(Cliente12.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnrecoverableKeyException ex) {
            Logger.getLogger(Cliente12.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
