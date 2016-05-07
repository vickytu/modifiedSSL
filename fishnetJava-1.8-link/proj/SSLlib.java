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
    public SSLState sslState;
    private Rand gen = null;
    private int pubKey = null;
    private int privKey = null;

    private int symKey;

    public String ver = null;
    public String cipher = null;
    public int sessID = null;

    enum SSLState {
        // protocol states, all of these are after the action has been done, so HELO = HELO_SENT
        NEW,
        HELO,
        CERT, // client-only
        S_DONE, // client-only
        C_KEYX, // server-only
        FINISHED,
        DONE,
        SHUTDOWN 
    }

    public SSLlib(TCPSock sock, TCPManager tcpMan) {
        this.sock = sock;
        this.tcpMan = tcpMan;
        this.sessID = 0;
        this.sslState = SSLState.NEW;
        
    }

    /*Return: 0 if 
        TLS/SSL handshake unsuccessful but was shut down controlled and by the specifications of the TLS/SSL protocol. Call SSL_get_error() with the return value ret to find out the reason.
        1 if handshake was successful, connection established
        < 0 if handshake unsuccessful bc fatal error. Again call SSL_get_error()
        > 1 if call me again, maybe
    */

    // initialize version and cipher for clients only
    public void ssl_init() {
        //gen (rand)
        ver = "1";
        cipher = "supersecretcipher";
        // read CA public key out of file CAkey_public.txt
    }

    public int ssl_accept(){
        // SERVER STATES ARE FOR THOSE MESSAGES IT HAS RECEIVED !!!!!!!!

        if (sock.state == TCPSock.State.ESTABLISHED) {
            return 2;
        }
        else if (sslState == SSLState.NEW) {
            // send HELO, CERT, and S_DONE, then change state
            sendHelo();
            sendCert();
            sendS_done();
            sslState = SSLState.HELO;
            return 2;

        }
        else if (sslState == SSLState.HELO) {
            return 2;

        }
        else if (sslState == SSLState.C_KEYX) {
            // tcpman already called a method in here to deal with c_keyx
            return 2;

        }
        else if (sslState == SSLState.FINISHED) {
            // send FINISHED
            sslState = SSLState.DONE;
            sock.state = TCPSock.State.ESTABLISHED;
            return 1;

        }
        else {
            //error
        }
        return 0;
    }

    /*Return: same as ssl_accept*/
    public int ssl_connect(){
        // CLIENT STATES ARE FOR THOSE MESSAGES IT IS EXPECTING !!!!!!!!
        if(sock.state == TCPSock.ESTABLISHED) {
            sock.state = TCPSock.HANDSHAKE;
            //send HELO
            return 2;

        } 
        else if (sslState == SSLState.HELO) {
            return 2;
        }
        else if (sslState == SSLState.CERT) {
            // tcpman called something to deal with helo
            return 2;
        }
        else if (sslState == SSLState.S_DONE) {
            // tcpman called something to deal with cert
            return 2;

        }
        else if (sslState == SSLState.FINISHED) {
            // tcpman called stuff to send C_KEYX and FINISHED
            return 2;
        }
        else if (sslState == SSLState.DONE) {
            return 1;
            
        }
        else {
            //error
        }


        return 0;
    }

    public boolean isNew() {
        return (sslState == SSLState.NEW);
    }
    public boolean isHelo() {
        return (sslState == SSLState.HELO);
    }
    public boolean isCert() {
        return (sslState == SSLState.CERT);
    }
    public boolean isS_Done() {
        return (sslState == SSLState.S_DONE);
    }
    public boolean isC_Keyx() {
        return (sslState == SSLState.C_KEYX);
    }
    public boolean isFinished() {
        return (sslState == SSLState.FINISHED);
    }
    public boolean isDone() {
        return (sslState == SSLState.DONE);
    }

    public void setNew() {
        sslState = SSLState.NEW;
    }
    public void setHelo() {
        sslState = SSLState.HELO;
    }
    public void setCert() {
        sslState = SSLState.CERT;
    }
    public void setS_Done() {
        sslState = SSLState.S_DONE;
    }
    public void setC_Keyx() {
        sslState = SSLState.C_KEYX;
    }
    public void setFinished() {
        sslState = SSLState.FINISHED;
    }
    public void setDone() {
        sslState = SSLState.DONE;
    }

    // FUNCTIONS TO MAKE

    /*Signature: int ssl_read(SSL *ssl, void *buf, int num)
            Return:  >0 if successful, w/number of bytes read
           0 if unsuccessful, but clean (maybe have been shutdown)
           <0 if unsuccessful, but needs action, some sort of error*/
    public int ssl_read(byte[] buf, int pos, int len){
        int bytesRead = 0;

        return bytesRead;
    }

    /*Signature: int ssl_write (SSL *ssl, const void *buf, int num)
        Return: same as ssl_read*/
    public int ssl_write(){
        return 0;   
    }

    /*Signature: int ssl_shutdown(SSL *ssl)
            Return: 0 shutdown not yet finished, call shutdown again if want a bidirectional shutdown
            1 shutdown successfully completed
            -1 shutdown unsuccessful bc of fatal error/other bad things*/
    public int ssl_shutdown(){
        return 0;
    }

    public void sendCert() {

        //write the certificate signing request



        //simulate certifying authority:
            //get private key from CAkey_private.txt
            //sign cert with SHA2 hash and key

        //pack message, signature into byte array payload
        sslSendPacket(Transport.CERT, payload);

    }

    public int parseCert(byte[] payload) {
        //unpack payload
        //split into message and signature
        //get public key from CAkey_public.txt
        //compare hash(message) with decrypt(signature)

    }

}