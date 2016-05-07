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
import java.io.*;
import java.security.*;
import java.security.spec.*;

public class SSLlib{

    public TCPSock sock;
    public TCPManager tcpMan;
    public SSLState sslState;
    private Random gen = null;
    private String pubKey = null;
    private String privKey = null;

    private String symKey;

    public String ver = null;
    public String cipher = null;
    public int sessID = null;

    public String domain = "isitbagelbrunch.com";
    public String organization = "VFD";
    public String country = "Genovia";

    public int rand_c;
    public int rand_s;

    public boolean die = false;

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
        this.gen = new Random();
    }

    public void sendHelo(){
        String helo = "";
        if (sock.isServer == true){
            rand_s = gen.nextInt(); //may have problems if sendHelo is called multiple times
            helo = String.format("%s, %s, %d, %d", ver, cipher, sessID, rand_s);
        }else{
            rand_c = gen.nextInt();
            helo = String.format("%s, %s, %d, %d", ver, cipher, sessID, rand_c);
        }
        byte[] payload = helo.getBytes(StandardCharsets.UTF_8); 
        sslSendPacket(Treanport.HELO, payload);
    }

    public void parseHelo(byte[] pay){
        String helo = new String(pay, StandardCharsets.UTF_8);
        String delims = "[,]";
        String[] tokens = helo.split(delims);
        ver = token[0];
        cipher = token[1];
        sessID = Integer.parseInt(token[2]);
        int rand = Integer.parseInt(token[3]);
        if (sock.isServer == true){
            rand_c = rand;
        }else{
            rand_s = rand;
        }        
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
        //read CA public key out of file CAkey_public.txt?
    }

    public int ssl_accept(){
        // SERVER STATES ARE FOR THOSE MESSAGES IT HAS RECEIVED !!!!!!!!

        if(die) {
            return -1;
        }

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
            sendHelo();
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
	
	// only called if is client
	public int sendKey() {
		// generate pre-master secret with rand_s
		int pms = gen.nextInt();
		// encrypt pms with public key (RSA)
		Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		c.init(Cipher.ENCRYPT_MODE, pubKey);
		byte[] pmsEncrypted = c.doFinal(pms.getBytes("UTF-8"));
		sslSendPacket(Transport.C_KEYX, pmsEncrypted);
		
		// after this, generate symmetric key w/PMS & rand_s and rand_c (RC4)
		// what input is needed?
		symKey = genSymKey();
		// return success or failure
		return 1;
	}
	
	public int parseKey(byte[] pay) {
		// decrypt pms with private key (RSA)
		Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		c.init(Cipher.DECRYPT_MODE, privKey);
		byte[] pms = c.doFinal(pay);
		// after this, generate symmetric key w/PMS & rand_s and rand_c
		symKey = genSymKey();
		// return success or failure
		return 1;
	}
	
	public int getSymKey() {
		// KeyGenerator keyGen = 
		// generate symkey with pms, rand_s, rand_c
		// sooooomehow...
		// return something (should be the symKey, dunno what it should be yet)
        return 1;
	}
	
	// make packet times which can be sent 
	public PacketTime sslSendPacket(int type, byte[] payload) {
		// define payload here
		Transport t;
		try {
            t = new Transport(sock.localPort, sock.destPort, type, sock.windowSize, sock.seqNum, payload);
        } catch (Exception e) {
            System.out.println("Error caught: " + e.getMessage());
            return -1;
        }
		PacketTime pt = new PacketTime(t, tcpMan.getMan().now());
		return pt;
	}

    public void sendCert() {

        //write the certificate signing request
        String cert = "";
        cert = String.format("%s, %s, %s, %s,", domain, organization, country, String(pubKey.getBytes("UTF-8")));

        //simulate certifying authority: 
        // (adapted from http://stackoverflow.com/questions/11410770/load-rsa-public-key-from-file)
            //get private key from CAkey_private.der
            File f = new File("CAkey_private.der");
            FileInputStream fis = new FileInputStream(f);
            DataInputStream dis = new DataInputStream(fis);
            byte[] keyBytes = new byte[(int)f.length()];
            dis.readFully(keyBytes);
            dis.close();
            fis.close();

            PKCS8EncodedKeySpec spec =
              new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey caPrivateKey = kf.generatePrivate(spec);

            //sign cert with SHA2 hash and key
            String signature = "";
            try {
                Signature sign = Signature.getInstance("SHA2withRSA");
                sign.initSign(caPrivateKey);
                sign.update(cert.getBytes("UTF-8"));
                //CHECK THIS vvvv
                signature = String(sign.sign(), "UTF-8");
            } catch (Exception ex) {
                System.out.print(ex);
            }

        //pack message, signature into byte array payload
        String payloadString = cert + signature;
        byte[] payload = payloadString.getBytes();
        sslSendPacket(Transport.CERT, payload);

    }

    public boolean parseCert(byte[] payload) {
        //unpack payload, split into message and signature
        String payloadString = String(payload);
        String[] payloadParse = payloadString.split(",", 5);
        String message = payloadParse[0] + payloadParse[1] + payloadParse[2] + payloadParse[3];
        String signature = payloadParse[4];
        if(!payloadParse[0].equals(domain)) {
            System.out.println("Error: SSL domain does not match");
            return false;
        }
        //get public key from CAkey_public.der
        // (adapted from http://stackoverflow.com/questions/11410770/load-rsa-public-key-from-file)
        File f = new File("CAkey_public.der");
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int)f.length()];
        dis.readFully(keyBytes);
        dis.close();
        fis.close();

        X509EncodedKeySpec spec =
          new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey caPublicKey = kf.generatePublic(spec);

        //verify signed message
        try {
            Signature sign = Signature.getInstance("SHA1withRSA");
            sign.initVerify(caPublicKey);
            sign.update(message.getBytes("UTF-8"));
            return sign.verify(signature.getBytes("UTF-8"));
        } catch (Exception ex) {
            System.out.print(ex);
        }
    }

    public void sendFinished() {
        //send the digest
        helo = String.format("%s, %s, %d, %d", ver, cipher, sessID, rand_s);
        byte[] buffer = helo.getBytes(StandardCharsets.UTF_8);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(buffer);
        byte [] digest = md.digest();
        sslSendPacket(Transport.FINISHED, digest);
    }

    public int parseFinished(byte[] payload) {
        //receive the digest
    }


}