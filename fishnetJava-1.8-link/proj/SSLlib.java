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
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.*;
import java.util.Base64.*;
import java.nio.charset.StandardCharsets;


public class SSLlib{

    public TCPSock sock;
    public TCPManager tcpMan;
    public SSLState sslState;
    private SecureRandom gen = null;
    private PublicKey pubKey = null;
    private PrivateKey privKey = null;
	private byte[] pms = null;
    private SecretKeySpec symKey = null;  
    private Cipher masterCipher = null;   

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
    private boolean isKeyDone = false;
    private byte[] keyPay;


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
        //System.out.println("ssl_accept has been called");
        if(die) {
            return -1;
        }

        if(sock.state == TCPSock.State.ESTABLISHED) {
            //System.out.println("socket established, returning 1");
            return 1;
        }

        if (sock.state == TCPSock.State.PREESTABLISHED) {
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

        //System.out.println("ssl_connect has been called");

        if(die) {
            return -1;
        }

        if(sock.state == TCPSock.State.ESTABLISHED) {
            //System.out.println("socket established, returning 1");
            return 1;
        }
        if(sock.state == TCPSock.State.PREESTABLISHED) {
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
        try {
            return masterCipher.update(cipherText);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }

    // encrypt plaintext using the symmetric key
    public byte[] ssl_encrypt(byte[] plainText){
        if(symKey == null) {
            System.out.println("Warning: data is not SSL encrypted");
            return plainText;
        }

        //System.out.println("PLAIN TEXT: " +plainText);
        byte[] newBuf;
        try {
            newBuf = masterCipher.update(plainText);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        //System.out.println(newBuf.length);
        return newBuf;
           
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

        try{
            String helo = String.format("%s,%s,%d", ver, cipher, sessID);;
            //String str = "";
            byte[] rand;
            if (sock.isServer == true){
                System.out.println("Server:");
                rand_s = new byte[32];
                gen.nextBytes(rand_s);
                rand = rand_s;
                //rand_s = gen.nextInt(); //may have problems if sendHelo is called multiple times
                //str = new String(rand_s, "StandardCharsets.US_ASCII");
                //str = Base64.getEncoder().encodeToString(rand_s);
            } else {
                System.out.println("Client:");
                rand_c = new byte[32];
                gen.nextBytes(rand_c);
                rand = rand_c;
                //rand_c = gen.nextInt();//may have problems if sendHelo is called multiple times
                //str = Base64.getEncoder().encodeToString(rand_c);
            }
            byte[] helo1 = helo.getBytes("UTF-8"); 
            byte[] payload = new byte[32 + helo1.length];
            System.arraycopy(rand, 0, payload, 0, 32);
            System.arraycopy(helo1, 0, payload, 32, helo1.length);
            sslSendPacket(Transport.HELO, payload);
            System.out.println("HELO sent");
        }catch(Exception ex){
            ex.printStackTrace();
        }
    }

    // parse through a received HELO transport, saving relevant fields
    public void parseHelo(byte[] pay){
        try{
            byte[] rand = Arrays.copyOfRange(pay, 0, 32);
            byte[] payload = Arrays.copyOfRange(pay, 32, pay.length);
            String helo = new String(payload, "UTF-8");
            String delims = "[,]";
            String[] tokens = helo.split(delims);
            ver = tokens[0];
            cipher = tokens[1];
            sessID = Integer.parseInt(tokens[2]);
            //int rand = Integer.parseInt(tokens[3]);
            //byte[] rand = Base64.getDecoder().decode(tokens[3]);
            System.out.printf("length: %d", rand.length);
            if (sock.isServer == true){
                rand_c = rand;
            }else{
                rand_s = rand;
            }

            System.out.println("HELO received and parsed");
        }catch(Exception ex){
            ex.printStackTrace();
        }        
    }

    // write and sign a certificate into a CERT transport and send it out
    public void sendCert() {

        //write the certificate signing request
        String cert = "";
        try {
            String pubKeyString = Base64.getEncoder().encodeToString(pubKey.getEncoded());
            System.out.println(pubKey.getEncoded());
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
        System.out.println("sending key");
		try {
			// create Pre-Master Secret - 48 random bytes, with padding to fill modulus of 128 bytes
			SecureRandom secRand = new SecureRandom();
			pms = new byte[48];

			secRand.nextBytes(pms);

            String str3 = Base64.getEncoder().encodeToString(pms);
            System.out.println("CLIENT PMS: " + str3);
			byte[] padding = new byte[57];
			secRand.nextBytes(padding);
			byte[] pmsPacket = new byte[105];
			System.arraycopy(pms, 0, pmsPacket, 0, 48);
			System.arraycopy(padding, 0, pmsPacket, 48, 57);

			
			// encrypt Pre-Master Secret with server's public key
			Cipher c = Cipher.getInstance("RSA/ECB/NoPadding");
			c.init(Cipher.ENCRYPT_MODE, pubKey);
			byte[] pmsEncrypted = c.doFinal(pmsPacket);

			System.out.println("sent length: " + pmsEncrypted.length);
			// send Pre-Master Secret 
			sslSendPacket(Transport.C_KEYX, pmsEncrypted);
            System.out.println("sent key");
			
			genSymKey();

            String str1 = Base64.getEncoder().encodeToString(symKey.getEncoded());
            System.out.println("CLIENT MASTER SECRET: " + str1);

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

            if (keyPay == null) {
                keyPay = new byte[128];
                System.arraycopy(pay, 0, keyPay, 0, pay.length);
                return 0;
            }
            else {
                System.arraycopy(pay, 0, keyPay, 105, pay.length);
    			// decrypt pms with private key (RSA), remove padding
    			Cipher c = Cipher.getInstance("RSA/ECB/NoPadding");
    			c.init(Cipher.DECRYPT_MODE, privKey);

    			byte[] pmsPacket = c.doFinal(keyPay);
    			pms = new byte[48];
    			System.arraycopy(pmsPacket, 0, pms, 0, 48);

                isKeyDone = true;
                String str = Base64.getEncoder().encodeToString(pmsPacket);
                System.out.println("SERVER PMS: " + str);
    			
    			// turn byte[] into symmetric key by method
    			genSymKey();
                String str1 = Base64.getEncoder().encodeToString(symKey.getEncoded());
                System.out.println("SERVER MASTER SECRET: " + str1);
            }
			
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
        System.out.println("in genSymKey");
		
		try {
			byte[] pmsFirst = new byte[24];
			System.arraycopy(pms, 0, pmsFirst, 0, 24);
			byte[] pmsSecond = new byte[24];
			System.arraycopy(pms, 24, pmsSecond, 0, 24);
			
			byte[] seed = new byte[64];
			System.arraycopy(rand_c, 0, seed, 0, 32);
			System.arraycopy(rand_s, 0, seed, 32, 32);
			
			Mac sha1_HMAC = Mac.getInstance("HmacSHA1");
			SecretKeySpec pmsKey1 = new SecretKeySpec(pmsFirst, "HmacSHA1");
			sha1_HMAC.init(pmsKey1);
			
			Mac md5_HMAC = Mac.getInstance("HmacMD5");
			SecretKeySpec pmsKey2 = new SecretKeySpec(pmsSecond, "HmacMD5");
			md5_HMAC.init(pmsKey2);
			
			byte[] p_hash1prep = sha1_HMAC.doFinal(seed);
            byte[] p_hash1 = new byte[p_hash1prep.length];
            System.arraycopy(p_hash1prep, 0, p_hash1, 0, p_hash1prep.length);

			while(p_hash1.length < 16) {
				byte[] newseed = new byte[64 + p_hash1.length];
				System.arraycopy(p_hash1, 0, newseed, 0, p_hash1.length);
				System.arraycopy(seed, 0, newseed, p_hash1.length, 64);
				//seed1 = newseed;
				p_hash1prep = sha1_HMAC.doFinal(newseed);
                byte[] p_hashnew = new byte[p_hash1.length + p_hash1prep.length];
                System.arraycopy(p_hash1, 0, p_hashnew, 0, p_hash1.length);
                System.arraycopy(p_hash1prep, 0, p_hashnew, p_hash1.length, p_hash1prep.length);
                p_hash1 = p_hashnew;
				
			}
			
			byte[] p_hash2prep = md5_HMAC.doFinal(seed);
            byte[] p_hash2 = new byte[p_hash2prep.length];
            System.arraycopy(p_hash2prep, 0, p_hash2, 0, p_hash2prep.length);

			while(p_hash2.length < 16) {

                byte[] newseed = new byte[64 + p_hash2.length];
                System.arraycopy(p_hash2, 0, newseed, 0, p_hash2.length);
                System.arraycopy(seed, 0, newseed, p_hash2.length, 64);
                //seed1 = newseed;
                p_hash2prep = md5_HMAC.doFinal(newseed);
                byte[] p_hashnew = new byte[p_hash2.length + p_hash2prep.length];
                System.arraycopy(p_hash2, 0, p_hashnew, 0, p_hash2.length);
                System.arraycopy(p_hash2prep, 0, p_hashnew, p_hash2.length, p_hash2prep.length);
                p_hash2 = p_hashnew;

                /*System.out.println("stuck in second while loop");
				
				byte[] newseed = new byte[64 + p_hash2.length];
				System.arraycopy(p_hash2, 0, newseed, 0, p_hash2.length);
				System.arraycopy(seed, 0, newseed, p_hash2.length, p_hash2.length + 64);
				//seed1 = newseed;
				p_hash2 = md5_HMAC.doFinal(newseed); */
				
			}
			
			byte[] finalp1 = new byte[16];
			System.arraycopy(p_hash1, 0, finalp1, 0, 16);
			byte[] finalp2 = new byte[16];
			System.arraycopy(p_hash2, 0, finalp2, 0, 16);
			byte[] symKeyb = new byte[16];
			
			for (int i = 0; i < 16; i++) {
				symKeyb[i] = (byte)(finalp1[i] ^ finalp2[i]);
			}
			
			symKey = new SecretKeySpec(symKeyb, 0, 16, "ARCFOUR");

            masterCipher = Cipher.getInstance("ARCFOUR");
            if (sock.isServer)
                masterCipher.init(Cipher.DECRYPT_MODE, symKey);
            else
                masterCipher.init(Cipher.ENCRYPT_MODE, symKey);

		}
		catch (Exception e) {
			System.out.println("Error caught in genSymKey: ");
            e.printStackTrace();
		}
			
	}
	
	
    // If I am a client, I send the server a digest of the msgs I have sent (rand_c)
    // send a digest of the handshake transaction in a FINISHED transport
    public void sendFinished() {
        System.out.println("in sendFinished");
        //send the digest of messages sender has sent
        String finished = "";
        System.out.println("symkey in sendFinished: " + symKey.getEncoded().length);
        if (sock.isServer == true){
            System.out.println("sending from server");
            finished = String.format("%s,%s,%d,%s", ver, cipher, sessID, new String(rand_s, StandardCharsets.UTF_8));
        }else{
            System.out.println("sending from client");
            finished = String.format("%s,%s,%d,%s", ver, cipher, sessID, new String(rand_c, StandardCharsets.UTF_8));
        }
        byte[] buffer = finished.getBytes(StandardCharsets.UTF_8);
        try{
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(buffer);
            byte [] digest = md.digest();
            sslSendPacket(Transport.FINISHED, digest);
            System.out.println("FINISHED sent");
        }catch (NoSuchAlgorithmException e){
            System.err.println("NoSuchAlgorithmException: ");
            e.printStackTrace();
        }
    }

    // If I am a server, I check by hashing the msg I've received (rand_c)
    // parse through a received digest, verifying that it matches the local version of the transaction
    public int parseFinished(byte[] payload) {
        //receive the digest
        System.out.println("in parseFinished");
        String finished = "";
        System.out.println("symkey in parseFinished: " + symKey.getEncoded().length);
        if (sock.isServer == true){
            System.out.println("checking messages  from server");
            finished = String.format("%s,%s,%d,%s", ver, cipher, sessID, new String(rand_c, StandardCharsets.UTF_8));
        }else{
            finished = String.format("%s,%s,%d,%s", ver, cipher, sessID, new String(rand_s, StandardCharsets.UTF_8));
        }
        byte[] buffer = finished.getBytes(StandardCharsets.UTF_8);
        try{
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(buffer);
            byte [] digest = md.digest();
            if (Arrays.equals(digest, payload)){
                System.out.println("digests match");
                return 0;
            }
            
        }catch (NoSuchAlgorithmException e){

            System.err.println("NoSuchAlgorithmException: ");
            e.printStackTrace();
        }
        System.out.println("digests DON'T match");
        return -1;
    }

        // make packet times which are then sent 
    public int sslSendPacket(int type, byte[] payload) {
        
        int count = 0; // index of first byte to be written
        int len = payload.length;
        if(type == Transport.HELO) {
            System.out.println("SENDING A HELO!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        }
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
                tcpMan.sslSendPkt(sock.destAddr, pt, sock, sock.seqNum);
            }
        }
        return 1; // success
    }

}