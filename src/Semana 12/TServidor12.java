
package semana12;

import java.io.BufferedReader;
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
public class TServidor12 extends Thread {
        static final String CIPHER_MODE = "AES/CTR/NoPadding";
    static final String UNSAFE_PASS = "olamundo";
    
    private int ct;
    protected Socket s;
    DHParameterSpec dhS;
    Certificate caCert;
    KeyStore ksCert;
    
    TServidor12(Socket s, int c,  DHParameterSpec dh, KeyStore ksCert, Certificate caCert) {
        this.ct = c;
        this.s=s;
        this.dhS = dh;
        this.ksCert=ksCert;
        this.caCert=caCert;
        
    }
    
    public void run() {
        
        try {
            ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
            ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
            
          //certificado            
           Certificate[] certArray = ksCert.getCertificateChain("Servidor");
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
               /*
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
            
            //chave privada
           PrivateKey sigprivkey = (PrivateKey) ksCert.getKey("Servidor", "1234".toCharArray());
            
           //enviar certificado
           oos.writeObject(certPath);
           
           //receber o certificado
           CertPath clienteCertPath =(CertPath)ois.readObject();
           //receber chave publica para fazer a verificaçao
            X509Certificate clienteCert = (X509Certificate) clienteCertPath.getCertificates().get(0);
           
           //Certificate clienteCert =(Certificate) clienteCertPath.get(0);
           PublicKey clientePubKey = clienteCert.getPublicKey();
            
           byte[] Public_key=null;
           byte[] Private_key=null;       
           BufferedReader teclado = new BufferedReader(new InputStreamReader(System.in));
            
            //assinatura digital
            Signature sig=Signature.getInstance("SHA1withRSA");
            sig.initSign(sigprivkey);
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
            sig.initVerify(clientePubKey);
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
            Logger.getLogger(TServidor12.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SignatureException ex) {
            Logger.getLogger(TServidor12.class.getName()).log(Level.SEVERE, null, ex);
        }   catch (KeyStoreException ex) {
                Logger.getLogger(TServidor12.class.getName()).log(Level.SEVERE, null, ex);
            } catch (CertificateException ex) {
                Logger.getLogger(TServidor12.class.getName()).log(Level.SEVERE, null, ex);
            } catch (UnrecoverableKeyException ex) {
                Logger.getLogger(TServidor12.class.getName()).log(Level.SEVERE, null, ex);
            }
    }
}
