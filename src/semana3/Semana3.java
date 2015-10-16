/*
* To change this license header, choose License Headers in Project Properties.
* To change this template file, choose Tools | Templates
* and open the template in the editor.
*/
package semana3;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**///AES/CBC/PKCS5Padding

public class Semana3 {
    
    static String PASS="password";
    static String KS="KeyStore";
   
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, KeyStoreException, CertificateException, UnrecoverableKeyException, UnrecoverableEntryException, InvalidAlgorithmParameterException
    {
        String command;
        boolean exit = false; // quer sair?
        BufferedReader teclado = new BufferedReader(new InputStreamReader(System.in)); // input do teclado
        while (!exit) {
            System.out.print("$ ");
            command = teclado.readLine(); // ler uma linha do teclado
            args = command.split(" "); // separar linha por espaços
            switch (args[0]){
                case "-genkey":{
                    //funçao de gerar chave
                    
                    KeyGenerator kg = KeyGenerator.getInstance("AES");
                    kg.init(128);
                    //secret key
                    SecretKey key = kg.generateKey();
                    byte[] keyBytes=key.getEncoded();
                    
                    //cria uma entrada
                    FileOutputStream chave= new FileOutputStream(new File (KS));
                    KeyStore ks = KeyStore.getInstance("JCEKS");
                    ks.load(null,PASS.toCharArray());
                    
                    //fis=new FileInputStream("KeyStore");
                    SecretKeyEntry ske= new SecretKeyEntry(key);
                    
                    //colocar uma password
                    PasswordProtection pp=new PasswordProtection(args[2].toCharArray());
                    //criar nova chave
                    ks.setEntry(args[1], ske, pp);
                    ks.store(chave, PASS.toCharArray());
                    chave.close();
                }break;
                    
                case "-enc":{
                    //funçao de encriptar
                    
                    //ler a chave criada
                    FileInputStream chave= new FileInputStream(new File(KS));
                                             
                    //             
                    KeyStore ks = KeyStore.getInstance("JCEKS");
                    ks.load(chave,PASS.toCharArray());
                    
                    PasswordProtection pp=new PasswordProtection(args[2].toCharArray());
                    SecretKeyEntry entry= (SecretKeyEntry)ks.getEntry(args[1], pp);
                         
                    //encriptar a cifra
                    Cipher e = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    e.init(Cipher.ENCRYPT_MODE, entry.getSecretKey());
                    
                    //ler a mensagem
                    FileInputStream mensagem= new FileInputStream(new File(args[3]));
                    
                    //ficheiro com mensagem encriptada
                    FileOutputStream encript= new FileOutputStream(args[4]);
                    encript.write(e.getIV());
                    int n=0;
                    byte[] cifrado=new byte[200];
                    
                    byte[] men=new byte[200];
                    while((n=mensagem.read(men))!=-1)
                    {
                        cifrado=e.update(men);
                        encript.write(cifrado);
                    }
                    chave.close();
                    mensagem.close();
                    encript.close();
                    
                }break;
                    
                case "-dec":{
                    //funçao de desencriptar
                    //ler chave
                    
                    
                    FileInputStream chave= new FileInputStream(new File(KS));           
                    KeyStore ks = KeyStore.getInstance("JCEKS");
                    ks.load(chave,PASS.toCharArray());
                    PasswordProtection pp=new PasswordProtection(args[2].toCharArray());
                    SecretKeyEntry entry= (SecretKeyEntry)ks.getEntry(args[1], pp);
                    
                    //ler mensgaem encriptada
                    FileInputStream encript= new FileInputStream(new File(args[3]));
                    //mensagem desencriptada/original
                    FileOutputStream mensagem= new FileOutputStream(args[4]);
                            
                    byte[] iV=new byte[16];
                    encript.read(iV);
                    IvParameterSpec iVs=new IvParameterSpec(iV);
                    
                    Cipher e = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    e.init(Cipher.DECRYPT_MODE, entry.getSecretKey(),iVs);
                    
                    int n=0;
                    byte[] cifrado=new byte[200];
                    byte[] decifrado=new byte[200];
                    while((n=encript.read(cifrado))!=-1)
                    {
                        decifrado=e.update(cifrado);
                        mensagem.write(decifrado);
                    }
                    chave.close();
                    mensagem.close();
                    encript.close();
                }break;
            }
        }
    }
}


