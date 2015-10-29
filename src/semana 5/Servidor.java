
package semana.pkg5;
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
import static semana.pkg5.Cliente.UNSAFE_PASSWORD;
/**
 *
 * @author ASUS
 */


public class Servidor {

    static private int tcount;

    static public void main(String []args) {
        tcount = 0;
        try {
            ServerSocket ss = new ServerSocket(61467);


            while(true) {
                Socket s = ss.accept();
                tcount++;
                TServidor ts = new TServidor(s,tcount);
                ts.start();
            }
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
}