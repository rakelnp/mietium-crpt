/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package semana.pkg9;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 *
 * @author ASUS
 */
public class Assinatura {
    
    static public void main (String[] args) throws FileNotFoundException, IOException, NoSuchAlgorithmException{
        
            
            BufferedReader teclado = new BufferedReader(new InputStreamReader(System.in));
             
            //gerar chaves da assinatura
            KeyPairGenerator kpg_sig = KeyPairGenerator.getInstance("RSA");
            kpg_sig.initialize(1024);
            
            KeyPair kp_Sig = kpg_sig.generateKeyPair();
            PublicKey Public_key = kp_Sig.getPublic();
            PrivateKey Private_key = kp_Sig.getPrivate();
            
            //guardar chave publica num ficheiro
            System.out.println("Inserir nome do ficheiro da chave publica");
            String save_pub=teclado.readLine();
            System.out.println("Inserir nome do ficheiro da chave privada");
            String save_priv=teclado.readLine();
                      
            ObjectOutputStream ficheiro_pub = new ObjectOutputStream(new FileOutputStream(save_pub));
            ObjectOutputStream ficheiro_priv = new ObjectOutputStream(new FileOutputStream(save_priv));

           ficheiro_pub.writeObject(Public_key);
           ficheiro_priv.writeObject(Private_key);

        }
    
}
