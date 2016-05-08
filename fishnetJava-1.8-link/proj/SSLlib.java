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
import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class SSLlib{

    public TCPSock sock;
    public TCPManager tcpMan;
    public SSLState sslState;
    private Random gen = null;
    private PublicKey pubKey = null;
    private PrivateKey privKey = null;

    private SecretKey symKey = null;     

    private PublicKey caPublicKey = null;
    private PrivateKey caPrivateKey = null;

    public String ver = null;
    public String cipher = null;
    public int sessID;

    private String domain = "isitbagelbrunch.com";
    private String organization = "VFD";
    private String country = "Genovia";

    private int rand_c;
    private int rand_s;

    public boolean die = false;

    public boolean isCertDone;
    private String certSoFar = "";

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
        sslSendPacket(Transport.HELO, payload);
    }

    public void parseHelo(byte[] pay){
        String helo = new String(pay, StandardCharsets.UTF_8);
        String delims = "[,]";
        String[] tokens = helo.split(delims);
        ver = tokens[0];
        cipher = tokens[1];
        sessID = Integer.parseInt(tokens[2]);
        int rand = Integer.parseInt(tokens[3]);
        if (sock.isServer == true){
            rand_c = rand;
        }else{
            rand_s = rand;
        }        
    }

    /*Return: 0 if 
        TLS/SSL handshake unsuccessful but was shut down controlled and by the specifications of the TLS/SSL protocol. 
        Call SSL_get_error() with the return value ret to find out the reason.
        1 if handshake was successful, connection established
        < 0 if handshake unsuccessful bc fatal error. Again call SSL_get_error()
        > 1 if call me again, maybe
    */

    // initialize version and cipher for clients only
    public void ssl_client_init() {
        //gen (rand)
        ver = "1";
        cipher = "supersecretcipher";
        sock.isServer = false;

        // Get trusted Certifying Authority's public key
        // get public key from CAkey_public.der
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
        caPublicKey = kf.generatePublic(spec);


    }

    public void ssl_server_init() {

        sock.isServer = true;

        //generate public and private keys
        // adapted from "https://examples.javacodegeeks.com/core-java/security/get-bytes-of-a-key-pair-example/"

        try {
            String algorithm = "RSA";

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
            keyPairGenerator.initialize(1024);
            KeyPair keyPair = keyPairGenerator.genKeyPair();
            PrivateKey privKey = keyPair.getPrivate();
            PublicKey pubKey = keyPair.getPublic();
        } catch (Exception ex) {
            System.out.print(ex);
        }

        //Get Certifying Authority private key 
        //(server will simulate external certifying authority by signing own certificate as "CA")
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
        caPrivateKey = kf.generatePrivate(spec);

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
        if(sock.state == TCPSock.State.ESTABLISHED) {
            sock.state = TCPSock.State.HANDSHAKE;
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
		// create symmetric key
		
		// encrypt symmetric key with public key (RSA)
		Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		c.init(Cipher.ENCRYPT_MODE, pubKey);
		//byte[] pmsEncrypted = c.doFinal(pms.getBytes("UTF-8"));
		sslSendPacket(Transport.C_KEYX, symEncrypted);
		
		// return success or failure
		return 1;
	}
	
	public int parseKey(byte[] pay) {
		// decrypt pms with private key (RSA)
		Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		c.init(Cipher.DECRYPT_MODE, privKey);
		byte[] pms = c.doFinal(pay);
		// after this, generate symmetric key w/PMS & rand_s and rand_c
		symKey = getSymKey();
		// return success or failure
		return 1;
	}
	
	// make packet times which are then sent 
	public int sslSendPacket(int type, byte[] payload) {
		
		int count = 0; // index of first byte to be written
		int len = payload.length;
		
		while (count < len) {
			
			int toWrite = Math.min((len - count), Transport.MAX_PAYLOAD_SIZE);
			byte[] bufWrite = Arrays.copyOfRange(payload, count, count + toWrite);
			Transport t;
			try {
				t = new Transport(sock.localPort, sock.destPort, type, sock.windowSize, sock.seqNum, bufWrite);
				
			} catch (Exception e) {
				System.out.println("Error caught: " + e.getMessage());
				return -1; // error
			}
			
			if (t != null) {
				PacketTime pt = new PacketTime(t, tcpMan.getMan().now());
				count += toWrite;
			}
		}
		return 1; // success
	}

    public void sendCert() {

        //write the certificate signing request
        String cert = "";
        cert = String.format("-----BEGIN CERTIFICATE-----%s, %s, %s, %s,", domain, organization, country, 
            new String(pubKey.getEncoded(), "UTF-8"));

        //simulate certifying authority: 
        // (adapted from http://stackoverflow.com/questions/11410770/load-rsa-public-key-from-file)
            //sign cert with SHA2 hash and key
            String signature = "";
            try {
                Signature sign = Signature.getInstance("SHA2withRSA");
                sign.initSign(caPrivateKey);
                sign.update(cert.getBytes("UTF-8"));
                signature = new String(sign.sign(), "UTF-8");
            } catch (Exception ex) {
                System.out.print(ex);
            }

        //pack message, signature into byte array payload
        String payloadString = cert + signature + "-----END CERTIFICATE-----";
        byte[] payload = payloadString.getBytes();
        sslSendPacket(Transport.CERT, payload);

    }

    public boolean parseCert(byte[] payload) {
        
        //add payload to certSoFar
        String payloadString = new String(payload);
        if(payloadString.startsWith("-----BEGIN CERTIFICATE-----")) {
            isCertDone = false;
            payloadString = payloadString.replace("-----BEGIN CERTIFICATE-----", "");
        } if(payloadString.endsWith("-----END CERTIFICATE-----")) {
            isCertDone = true;
            payloadString = payloadString.replace("-----END CERTIFICATE-----", "");
        }
        certSoFar = certSoFar + payloadString;
        if(!isCertDone) {
            return true;
        }

        //parse string into message and signature
        String[] certParse = certSoFar.split(",", 5);
        String message = certParse[0] + certParse[1] + certParse[2] + certParse[3];
        String signature = certParse[4];
        if(!certParse[0].equals(domain)) {
            System.out.println("Error: SSL domain does not match");
            return false;
        }

        //verify signed message
        try {
            Signature sign = Signature.getInstance("SHA1withRSA");
            sign.initVerify(caPublicKey);
            sign.update(message.getBytes("UTF-8"));
            if(!sign.verify(signature.getBytes("UTF-8"))) {
                System.out.println("Error: Could not verify SSL certificate");
                return false;
            }
        } catch (Exception ex) {
            System.out.print(ex);
        }

        //save server's public key from the cert
        byte[] pubKeyBytes = certParse[3].getBytes("UTF-8");
        X509EncodedKeySpec spec =
          new X509EncodedKeySpec(pubKeyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pubKey = kf.generatePublic(spec);

        return true;


    }

    public void sendS_done() {
        byte[] empty = new byte[0];
        sslSendPacket(Transport.S_DONE, empty);
    }

    public void sendFinished() {
        //send the digest of messages sender has sent
        String finished = "";
        String encodedKey = Base64.getEncoder().encodeToString(symKey.getEncoded()); //symKey is type SecretKey
        if (sock.isServer == true){
            finished = String.format("%s, %s, %d, %d", ver, cipher, sessID, rand_s);
        }else{
            finished = String.format("%s, %s, %d, %d", ver, cipher, sessID, rand_c, encodedKey);
        }
        byte[] buffer = finished.getBytes(StandardCharsets.UTF_8);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(buffer);
        byte [] digest = md.digest();
        sslSendPacket(Transport.FINISHED, digest);
    }

    //return 0 on success, -1 if fail
    public int parseFinished(byte[] payload) {
        //receive the digest
        String finished = "";
        String encodedKey = Base64.getEncoder().encodeToString(symKey.getEncoded());
        if (sock.isServer == true){
            finished = String.format("%s, %s, %d, %d", ver, cipher, sessID, rand_s);
        }else{
            finished = String.format("%s, %s, %d, %d", ver, cipher, sessID, rand_c, encodedKey);
        }
        byte[] buffer = finished.getBytes(StandardCharsets.UTF_8);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(buffer);
        byte [] digest = md.digest();
        if (Arrays.equals(digest, payload)){
            return 0;
        }
        return -1;
    }


}