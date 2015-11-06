
package semana.pkg7;

import java.io.File;
import java.io.FileOutputStream;
import java.net.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.lang.Thread;
import java.net.Socket;
import java.security.KeyStore;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import semana.pkg7.TServidor7;

/**
 *
 * @author ASUS
 */


public class Servidor7 {

    static private int tcount;

    static public void main(String []args) {
        tcount = 0;
        try {
            ServerSocket ss = new ServerSocket(61467);


            while(true) {
                Socket s = ss.accept();
                tcount++;
                TServidor7 ts = new TServidor7(s,tcount);
                ts.start();
            }
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
}