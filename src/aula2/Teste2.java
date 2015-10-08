/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package aula2;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author ASUS
 */
public class Teste2 {
    
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException
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
                KeyGenerator kg = KeyGenerator.getInstance("RC4");
                kg.init(128);
                SecretKey key = kg.generateKey();
                byte[] keyBytes=key.getEncoded();
                //Ficheiro chave- guarda a chave gerada
                FileOutputStream chave= new FileOutputStream(args[1]);
                chave.write(keyBytes);
                chave.close();
    }break;
        
        case "-enc":{
               //funçao de encriptar
               
            //ler a chave criada
            FileInputStream chave= new FileInputStream(new File(args[1]));
             //ler um array de bytes
            byte[] bytes = new byte[16];
            chave.read(bytes);
                
            //ler a mensagem          
            FileInputStream mensagem= new FileInputStream(new File(args[2]));
                
            //ficheiro com mensagem encriptada
            FileOutputStream encript= new FileOutputStream(args[3]);           
           
           //conversão da chave
            SecretKey key = new SecretKeySpec(bytes, "RC4");
            Cipher e = Cipher.getInstance("RC4");
            e.init(Cipher.ENCRYPT_MODE, key);
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
                FileInputStream chave= new FileInputStream(new File(args[1]));
                byte[] bytes = new byte[16];
                chave.read(bytes);
                //ler mensgaem encriptada
                FileInputStream encript= new FileInputStream(new File(args[2]));
                //mensagem desencriptada/original
                FileOutputStream mensagem= new FileOutputStream(args[3]);  
                
           
            SecretKey key = new SecretKeySpec(bytes, "RC4");
            Cipher e = Cipher.getInstance("RC4");
            e.init(Cipher.DECRYPT_MODE, key);
           
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