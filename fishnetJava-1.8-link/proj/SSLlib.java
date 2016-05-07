/**
 * <p>Title: CPSC 433/533 Programming Assignment</p>
 *
 * <p>Description: SSL implementation</p>
 *
 * <p>Copyright: Copyright (c) 2016</p>
 *
 * <p>Company: Yale University</p>
 *
 * @author Shona Hemmady, Amelia Grace Holcomb, Vicky Tu
 * @version 1.0
 */
import java.util.*;
import java.nio.ByteBuffer;
import java.lang.Math;

public class SSLlib{

    public TCPSock sock;
    public TCPManager tcpMan;
    private Rand gen;
    private int pubKey;
    private int privKey;

    private int symKey;

    public String ver;
    public String cipher;
    public int sessID;

    public SSLlib(TCPSock sock, TCPManager tcpMan) {
        this.sock = sock;
        this.tcpMan = tcpMan;
        this.sessID = 0;
    }

    /*Return: 0 if 
        TLS/SSL handshake unsuccessful but was shut down controlled and by the specifications of the TLS/SSL protocol. Call SSL_get_error() with the return value ret to find out the reason.
        1 if handshake was successful, connection established
        < 0 if handshake unsuccessful bc fatal error. Again call SSL_get_error()
    */

    public static int ssl_accept(){
        return 0;
    }

    /*Return: same as ssl_accept*/
    public static int ssl_connect(){
        return 0;
    }

    /*Signature: int ssl_read(SSL *ssl, void *buf, int num)
            Return:  >0 if successful, w/number of bytes read
           0 if unsuccessful, but clean (maybe have been shutdown)
           <0 if unsuccessful, but needs action, some sort of error*/
    public static int ssl_read(byte[] buf, int pos, int len){
        int bytesRead = 0;

        return bytesRead;
    }

    /*Signature: int ssl_write (SSL *ssl, const void *buf, int num)
        Return: same as ssl_read*/
    public static int ssl_write(){
        return 0;   
    }

    /*Signature: int ssl_shutdown(SSL *ssl)
            Return: 0 shutdown not yet finished, call shutdown again if want a bidirectional shutdown
            1 shutdown successfully completed
            -1 shutdown unsuccessful bc of fatal error/other bad things*/
    public static int ssl_shutdown(){
        return 0;
    }

}