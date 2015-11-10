/*
* To change this license header, choose License Headers in Project Properties.
* To change this template file, choose Tools | Templates
* and open the template in the editor.
*/
package semana.pkg7;

import java.net.*;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.lang.Thread;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
/**
 *
 * @author ASUS
 */
public class Cliente7 {
    static final String CIPHER_MODE="AES/CTR/NoPadding";
    static SecureRandom r= new SecureRandom()  ;
    static final BigInteger P= new BigInteger ("99494096650139337106186933977618513974146274831566768179581759037259788798151499814653951492724365471316253651463342255785311748602922458795201382445323499931625451272600173180136123245441204133515800495917242011863558721723303661523372572477211620144038809673692512025566673746993593384600667047373692203583");
    static final BigInteger G= new BigInteger ("44157404837960328768872680677686802650999163226766694797650810379076416463147265401084491113667624054557335394761604876882446924929840681990106974314935015501571333024773172440352475358750668213444607353872754650805031912866692119819377041901642732455911509867728218394542745330014071040326856846990119719675");
    static final BigInteger x= new BigInteger (P.bitLength(),r);
    static public void main(String []args) {
        try {
            Socket s = new Socket("localhost",61467);
            
            ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
            ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
            //Acordo de Chaves
            //calcular a chave g^x e por fim o módulo de P
            BigInteger Gx=G.modPow(x,P);
            //enviar g^x
            oos.writeObject(Gx);
            //receber Gy
            BigInteger Gy=(BigInteger) ois.readObject();
            
            //calgular Gxy
            BigInteger Gxy= Gy.modPow(x,P);
            System.out.println("Gxy"+Gxy);
            MessageDigest sha256=MessageDigest.getInstance("SHA-256");
            byte rawbits[]=sha256.digest(Gxy.toByteArray());
            SecretKey key =new SecretKeySpec(rawbits,0, 16,"AES");
            
            //encriptar a cifra
            Cipher e = Cipher.getInstance(CIPHER_MODE);
            //IvParameterSpec iv=new IvParameterSpec(rawbits,16,16);
            e.init(Cipher.ENCRYPT_MODE, key);
            Mac m=Mac.getInstance("HmacSHA1");
            m.init(new SecretKeySpec(rawbits,16,16,"HmacSHA1"));
            
            byte iv[]=e.getIV();
            oos.writeObject(iv);
            
            
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
                }
            }
            oos.write(e.doFinal());
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
}
