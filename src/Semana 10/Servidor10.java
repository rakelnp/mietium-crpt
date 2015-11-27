/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package semana.pkg9;

import java.net.ServerSocket;
import java.net.Socket;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import javax.crypto.spec.DHParameterSpec;

/**
 *
 * @author ASUS
 */
public class Servidor10
{

    static private int tcount;
    
    static public void main(String []args) {
        tcount = 0;
        try{
            //gerar par de chaves publicas
            AlgorithmParameterGenerator apg = AlgorithmParameterGenerator.getInstance("DH");
            apg.init(1024);
            AlgorithmParameters parametros = apg.generateParameters();
            // converter parametros para Diffie-Hellman
            DHParameterSpec dh = (DHParameterSpec)parametros.getParameterSpec(DHParameterSpec.class);
            
            ServerSocket ss = new ServerSocket(61919);
            while(true) {
                Socket s = ss.accept();
                
                tcount++;
                TServidor10 ts = new TServidor10(s,tcount,dh);
                
                System.out.println("<"+tcount+">");
                ts.start();
            }
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
    
}
