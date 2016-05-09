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
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64.*;


public class SSLlib{

    public TCPSock sock;
    public TCPManager tcpMan;
    public SSLState sslState;
    private SecureRandom gen = null;
    private PublicKey pubKey = null;
    private PrivateKey privKey = null;
	private byte[] pms = null;
    private SecretKey symKey = null;     

    private PublicKey caPublicKey = null;
    private PrivateKey caPrivateKey = null;

    public String ver = null;
    public String cipher = null;
    public int sessID;

    private String domain = "isitbagelbrunch.com";
    private String organization = "VFD";
    private String country = "Genovia";

    private byte[] rand_c;
    private byte[] rand_s;

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
        this.gen = new SecureRandom();
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
        sock.state = TCPSock.State.HANDSHAKE;
        sslState = SSLState.HELO;
        System.out.println("set HELO, set HANDSHAKE");
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

//////////      INITIALIZATIONS            //////////////

    // initialization for clients only
    public void ssl_client_init() {
        //gen (rand)
        ver = "1";
        cipher = "supersecretcipher";
        sock.isServer = false;

        // Get trusted Certifying Authority's public key
        // get public key from CAkey_public.der
        // (adapted from http://stackoverflow.com/questions/11410770/load-rsa-public-key-from-file)

        try {
            File f = new File("proj/CAkey_public.der");
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
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        


    }

    //initialization for servers only
    public void ssl_server_init() {

        sock.isServer = true;

        //generate public and private keys
        // adapted from 
        //"https://examples.javacodegeeks.com/core-java/security/get-bytes-of-a-key-pair-example/"

        try {
            String algorithm = "RSA";

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
            keyPairGenerator.initialize(1024);
            KeyPair keyPair = keyPairGenerator.genKeyPair();
            privKey = keyPair.getPrivate();
            pubKey = keyPair.getPublic();

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        //Get Certifying Authority private key 
        //(server will simulate external certifying authority by signing own certificate as "CA")
        // (adapted from http://stackoverflow.com/questions/11410770/load-rsa-public-key-from-file)
        //get private key from CAkey_private.der
        try {
            File f = new File("proj/CAkey_private.der");
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
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        

    }

//////////      MAJOR FUNCTIONS         //////////////


    // server side: accept an SSL connection on top of current TCP connection
    // returns < 1 on fatal SSL error
    // returns 1 on success
    // returns > 1 if handshake is still incomplete 
    public int ssl_accept(){
        // SERVER STATES ARE FOR THOSE MESSAGES IT HAS RECEIVED !!!!!!!!
        System.out.println("ssl_accept has been called");
        if(die) {
            return -1;
        }

        if (sock.state == TCPSock.State.ESTABLISHED) {
            System.out.println("Server state == ESTABLISHED");
            return 2;
        }

        else if (sslState == SSLState.NEW) {
            // send HELO, CERT, and S_DONE, then change state
            System.out.println("Server sending HELO, CERT, and S_DONE");
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
            System.out.println("accept error");
        }
    
        return 0;
    }

    // client side: initiate an SSL connection on top of current TCP connection
    // returns < 1 on fatal SSL error
    // returns 1 on success
    // returns > 1 if handshake is still incomplete    
    public int ssl_connect(){
        // CLIENT STATES ARE FOR THOSE MESSAGES IT IS EXPECTING !!!!!!!!

        System.out.println("ssl_connect has been called");

        if(die) {
            return -1;
        }

        if(sock.state == TCPSock.State.ESTABLISHED) {
            sock.state = TCPSock.State.HANDSHAKE;
            System.out.println("Client sock state == HANDSHAKE");
            sendHelo();
            sslState = SSLState.HELO;
            return 2;

        } 
        else if (sslState == SSLState.HELO) {
            System.out.println("Client state == HELO");
            return 2;
        }
        else if (sslState == SSLState.CERT) {
            // tcpman called something to deal with helo
            System.out.println("Client state == CERT");
            return 2;
        }
        else if (sslState == SSLState.S_DONE) {
            // tcpman called something to deal with cert
            System.out.println("Client state == S_DONE");
            return 2;

        }
        else if (sslState == SSLState.FINISHED) {
            // tcpman called stuff to send C_KEYX and FINISHED
            System.out.println("Client state == FINISHED");
            return 2;
        }
        else if (sslState == SSLState.DONE) {
            System.out.println("Client state == DONE");
            sock.state = TCPSock.State.ESTABLISHED;
            return 1;
            
        }
        else {
            //error
            System.out.println("connect error");
        }


        return 0;
    }

    // FUNCTIONS TO MAKE

    // decrypt ciphertext using the symmetric key
    public byte[] ssl_decrypt(byte[] cipherText){

        if(symKey == null) {
            System.out.println("Warning: data is not SSL decrypted");
            return cipherText;
        }
        
        return masterCipher.update(cipherText);

    }

    // encrypt plaintext using the symmetric key
    public byte[] ssl_encrypt(byte[] plainText){
        if(symKey == null) {
            System.out.println("Warning: data is not SSL encrypted");
            return plainText;
        }

        return masterCipher.update(plainText);
           
    }

    /*Signature: int ssl_shutdown(SSL *ssl)
            Return: 0 shutdown not yet finished, call shutdown again if want a bidirectional shutdown
            1 shutdown successfully completed
            -1 shutdown unsuccessful due to fatal error*/
    public int ssl_shutdown(){
        return 0;
    }

//////////      HELPER FUNCTIONS        //////////////

    // write a HELO transport and send it out
    public void sendHelo(){

        String helo = "";
        String str = "";
        if (sock.isServer == true){
            System.out.println("Server:");
            rand_s = new byte[32];
            gen.nextBytes(rand_s);
            //rand_s = gen.nextInt(); //may have problems if sendHelo is called multiple times
            str = new String(rand_s, StandardCharsets.UTF_8);
            helo = String.format("%s,%s,%d,%s", ver, cipher, sessID, rand_s);
        } else {
            System.out.println("Client:");
            rand_c = new byte[32];
            gen.nextBytes(rand_c);
            //rand_c = gen.nextInt();//may have problems if sendHelo is called multiple times
            str = new String(rand_c, StandardCharsets.UTF_8);
            helo = String.format("%s,%s,%d,%s", ver, cipher, sessID, rand_c);
        }
        byte[] payload = helo.getBytes(StandardCharsets.UTF_8); 
        sslSendPacket(Transport.HELO, payload);
        System.out.println("HELO sent");
    }

    // parse through a received HELO transport, saving relevant fields
    public void parseHelo(byte[] pay){
        String helo = new String(pay, StandardCharsets.UTF_8);
        String delims = "[,]";
        String[] tokens = helo.split(delims);
        ver = tokens[0];
        cipher = tokens[1];
        sessID = Integer.parseInt(tokens[2]);
        //int rand = Integer.parseInt(tokens[3]);
        byte[] rand = tokens[3].getBytes(StandardCharsets.UTF_8);
        if (sock.isServer == true){
            rand_c = rand;
        }else{
            rand_s = rand;
        }

        System.out.println("HELO received and parsed");        
    }

    // write and sign a certificate into a CERT transport and send it out
    public void sendCert() {

        //write the certificate signing request
        String cert = "";
        try {
            String pubKeyString = Base64.getEncoder().encodeToString(pubKey.getEncoded());
            cert = String.format("-----BEGIN CERTIFICATE-----%s,%s,%s,%sEND MESSAGE", 
                domain, organization, country, pubKeyString);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        //simulate certifying authority: 
        // (adapted from http://stackoverflow.com/questions/11410770/load-rsa-public-key-from-file)
            //sign cert with SHA2 hash and key
            String signature = "";
            try {
                Signature sign = Signature.getInstance("SHA1withRSA");
                sign.initSign(caPrivateKey);
                sign.update(cert.getBytes("UTF-8"));
                signature = Base64.getEncoder().encodeToString(sign.sign());
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        System.out.println(signature);

        //pack message, signature into byte array payload
        String payloadString = cert + signature + "-----END CERTIFICATE-----";
        byte[] payload = payloadString.getBytes();
        sslSendPacket(Transport.CERT, payload);
        System.out.println("CERT sent");

    }


    // parse through a received certificate, checking valid signature and correct domain name
    // save the enclosed public key
    public boolean parseCert(byte[] payload) {

        //add payload to certSoFar
        try {
            String payloadString = new String(payload, "UTF-8");
            if(payloadString.startsWith("-----BEGIN CERTIFICATE-----")) {
                isCertDone = false;
                payloadString = payloadString.replace("-----BEGIN CERTIFICATE-----", "");
            } 
            certSoFar = certSoFar + payloadString;

            if(certSoFar.endsWith("-----END CERTIFICATE-----")) {
                isCertDone = true;
                certSoFar = certSoFar.replace("-----END CERTIFICATE-----", "");
            }
            if(!isCertDone) {
                return true;
            } 
        } catch (Exception ex) {
            ex.printStackTrace();
        }


        System.out.println("parsing cert");
        //parse string into message and signature
        String[] certParse = certSoFar.split("END MESSAGE");
        String message = certParse[0];
        String[] messageParse = message.split(",", 4);
        String signature = certParse[1];

        if(!messageParse[0].equals(domain)) {
            System.out.println("Error: SSL domain does not match");
            return false;
        }

        //verify signed message
        try {
            Signature sign = Signature.getInstance("SHA1withRSA");
            sign.initVerify(caPublicKey);
            sign.update(("-----BEGIN CERTIFICATE-----" + message + "END MESSAGE").getBytes("UTF-8"));
            if(!sign.verify(Base64.getDecoder().decode(signature.getBytes("UTF-8")))) {
                System.out.println("Error: Could not verify SSL certificate");
                return false;
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        //save server's public key from the cert
        try {
            byte[] pubKeyBytes = Base64.getDecoder().decode(messageParse[3].getBytes("UTF-8"));
            X509EncodedKeySpec spec =
              new X509EncodedKeySpec(pubKeyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            pubKey = kf.generatePublic(spec);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        System.out.println("CERT parsed and received");

        return true;


    }

    // send an S_DONE transport
    public void sendS_done() {
        byte[] dummy = new byte[1];
        sslSendPacket(Transport.S_DONE, dummy);
        System.out.println("S_done sent");
    }
	
	// generate a symmetric key as specified in RFC2246, p11-12
    // send key in C_KEYX transport
	public int sendKey() {

		try {
			// create Pre-Master Secret - 48 random bytes, with padding to fill modulus of 128 bytes
			SecureRandom secRand = new SecureRandom();
			pms = new byte[48];
			secRand.nextBytes(pms);
			byte[] padding = new byte[57];
			secRand.nextBytes(padding);
			byte[] pmsPacket = new byte[105];
			System.arraycopy(pms, 0, pmsPacket, 0, 48);
			System.arraycopy(padding, 0, pmsPacket, 48, 57);
			
			// encrypt Pre-Master Secret with server's public key
			Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			c.init(Cipher.ENCRYPT_MODE, pubKey);
			byte[] pmsEncrypted = c.doFinal(pmsPacket);
			
			// send Pre-Master Secret 
			sslSendPacket(Transport.C_KEYX, pmsEncrypted);
			
			genSymKey();
			
			// create symmetric key -- SIMPLIFIED FOR NOW
			/* KeyGenerator keyGen = KeyGenerator.getInstance("AES");

			keyGen.init(128);	// to be really secure, should be 112~~~!!! 
                                    //also work with padding once we have PMS and stuff
			symKey = keyGen.generateKey();
			
			// encrypt symmetric key with public key (RSA)
			Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			c.init(Cipher.ENCRYPT_MODE, pubKey);
			byte[] symEncrypted = c.doFinal(symKey.getEncoded());
			sslSendPacket(Transport.C_KEYX, symEncrypted); */
			
		} catch (Exception e) {
			System.out.println("Error caught in sendKey: ");
            e.printStackTrace();
			return -1;
		}	
		// return success or failure
		return 1;
	}
	
    // parse through a received C_KEYX transport, saving key
	public int parseKey(byte[] pay) {

		try {
			// decrypt pms with private key (RSA), remove padding
			Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			c.init(Cipher.DECRYPT_MODE, privKey);
			byte[] pmsPacket = c.doFinal(pay);
			pms = new byte[48];
			System.arraycopy(pmsPacket, 0, pms, 0, 48);
			
			// turn byte[] into symmetric key by method
			genSymKey();
			
		} catch (Exception e) {
			System.out.println("Error caught in parseKey: ");
            e.printStackTrace();
			return -1;
		}

		return 1;
	}
	
	// generate symmetric key from Pre-Master Secret, rand_c, rand_s
	// split Pre-Master Secret into half, use one half with HMAC-SHA1 and other half
	// with HMAC-MD5 in combination with rand_c and rand_s
	public void genSymKey() {
		
		try {
			byte[] pmsFirst = new byte[24];
			System.arraycopy(pms, 0, pmsFirst, 0, 24);
			byte[] pmsSecond = new byte[24];
			System.arraycopy(pms, 0, pmsSecond, 0, 24);
			
			byte[] seed = new byte[64];
			System.arraycopy(rand_c, 0, seed, 0, 32);
			System.arraycopy(rand_s, 0, seed, 32, 32);
			
			Mac sha1_HMAC = Mac.getInstance("HmacSHA1");
			SecretKeySpec pmsKey1 = new SecretKeySpec(pmsFirst, "HmacSHA1");
			sha1_HMAC.init(pmsKey1);
			
			Mac md5_HMAC = Mac.getInstance("HmacMD5");
			SecretKeySpec pmsKey2 = new SecretKeySpec(pmsSecond, "HmacMD5");
			md5_HMAC.init(pmsKey2);
			
			byte[] p_hash1 = sha1_HMAC.doFinal(seed);
			while(p_hash1.length < 48) {
				
				byte[] newseed = new byte[64 + p_hash1.length];
				System.arraycopy(p_hash1, 0, newseed, 0, p_hash1.length);
				System.arraycopy(seed, 0, newseed, p_hash1.length, 64);
				//seed1 = newseed;
				p_hash1 = sha1_HMAC.doFinal(newseed);
				
			}
			
			byte[] p_hash2 = md5_HMAC.doFinal(seed);
			while(p_hash2.length < 48) {
				
				byte[] newseed = new byte[64 + p_hash2.length];
				System.arraycopy(p_hash2, 0, newseed, 0, p_hash2.length);
				System.arraycopy(seed, 0, newseed, p_hash2.length, p_hash2.length + 64);
				//seed1 = newseed;
				p_hash2 = md5_HMAC.doFinal(newseed);
				
			}
			
			byte[] finalp1 = new byte[48];
			System.arraycopy(p_hash1, 0, finalp1, 0, 48);
			byte[] finalp2 = new byte[48];
			System.arraycopy(p_hash2, 0, finalp2, 0, 48);
			byte[] symKeyb = new byte[48];
			
			for (int i = 0; i < 48; i++) {
				symKeyb[i] = (byte)(finalp1[i] ^ finalp2[i]);
			}
			
			symKey = new SecretKeySpec(symKeyb, 0, 48, "AES");
		}
		catch (Exception e) {
			System.out.println("Error caught in genSymKey: ");
            e.printStackTrace();
		}
			
	}
	
	

    // send a digest of the handshake transaction in a FINISHED transport
    public void sendFinished() {
        //send the digest of messages sender has sent
        String finished = "";
        String encodedKey = Base64.getEncoder().encodeToString(symKey.getEncoded()); 
                                                                    //symKey is type SecretKey
        if (sock.isServer == true){
            finished = String.format("%s,%s,%d,%s", ver, cipher, sessID, new String(rand_s, StandardCharsets.UTF_8));
        }else{
            finished = String.format("%s,%s,%d,%s,%s", ver, cipher, sessID, new String(rand_c, StandardCharsets.UTF_8), encodedKey);
        }
        byte[] buffer = finished.getBytes(StandardCharsets.UTF_8);
        try{
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(buffer);
            byte [] digest = md.digest();
            sslSendPacket(Transport.FINISHED, digest);
        }catch (NoSuchAlgorithmException e){
            System.err.println("NoSuchAlgorithmException: ");
            e.printStackTrace();
        }
    }

    // parse through a received digest, verifying that it matches the local version of the transaction
    public int parseFinished(byte[] payload) {
        //receive the digest
        String finished = "";
        String encodedKey = Base64.getEncoder().encodeToString(symKey.getEncoded());
        if (sock.isServer == true){
            finished = String.format("%s,%s,%d,%s", ver, cipher, sessID, new String(rand_s, StandardCharsets.UTF_8));
        }else{
            finished = String.format("%s,%s,%d,%s,%s", ver, cipher, sessID, new String(rand_c, StandardCharsets.UTF_8), encodedKey);
        }
        byte[] buffer = finished.getBytes(StandardCharsets.UTF_8);
        try{
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(buffer);
            byte [] digest = md.digest();
            if (Arrays.equals(digest, payload)){
                return 0;
            }
            
        }catch (NoSuchAlgorithmException e){
            System.err.println("NoSuchAlgorithmException: ");
            e.printStackTrace();
        }
        return -1;
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
                t = new Transport(sock.localPort, sock.destPort, type, 
                    sock.windowSize, sock.seqNum, bufWrite);
                
            } catch (Exception e) {
                System.out.println("Error caught: ");
                e.printStackTrace();
                return -1; // error
            }
            
            if (t != null) {
                PacketTime pt = new PacketTime(t, tcpMan.getMan().now());
                count += toWrite;
                tcpMan.sendPkt(sock.destAddr, pt, sock, sock.seqNum);
            }
        }
        return 1; // success
    }

}