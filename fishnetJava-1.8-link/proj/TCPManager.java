/**
 * <p>Title: CPSC 433/533 Programming Assignment</p>
 *
 * <p>Description: Fishnet TCP manager</p>
 *
 * <p>Copyright: Copyright (c) 2006</p>
 *
 * <p>Company: Yale University</p>
 *
 * @author Hao Wang
 * @version 1.0
 */
import java.util.*;

public class TCPManager {
    private Node node;
    public int addr;
    private Manager manager;
    // store hashtable
    private HashMap<String, TCPSock> sockHash;
    private boolean[] sockArr;
    private static final byte dummy[] = new byte[0];

    public TCPManager(Node node, int addr, Manager manager) {
        this.node = node;
        this.addr = addr;
        this.manager = manager;
        this.sockArr = new boolean[256]; 
        this.sockHash = new HashMap<String, TCPSock>();
    }

    /**
     * Start this TCP manager
     */
    public void start() {

    }

    public Manager getMan() {
        return manager;
    }

    /*
     * Begin socket API
     */

    /**
     * Create a socket
     *
     * @return TCPSock the newly created socket, which is not yet bound to
     *                 a local port
     */
    public TCPSock socket() {
        TCPSock tcpSock = new TCPSock(this);
        return tcpSock;
    }

    // add TCPSock to the hashmap
    // return 0 on success, -1 otherwise
    public int addSock(TCPSock sock, String hash) {
        if (sockHash.get(hash) != null) {
            return -1;
        } 
        else {
            sockHash.put(hash, sock);
            return 0;
        }

    }

    // check if localport is free, and if so, reserve it for socket
    // return 0 for success, -1 for failure
    public int reservePort(int localPort) {
        if (sockArr[localPort])
            return -1;
        else {
            sockArr[localPort] = true;
            return 0;
        }
    }

    // receive a packet and unpack it to find out where it goes
    // depending on the packet, either send the SYN, ACK, or FIN to the socket
    // and change seqNum if necessary
    // or write into its buffer
    public void receive(int from, byte[] transport) {

        Transport t = Transport.unpack(transport);
        int srcPort = t.getSrcPort();
        int destPort = t.getDestPort();
        int tSeqNum = t.getSeqNum();
        byte[] pay = t.getPayload();

        // search for TCPSock in hashmap by using source and destination
        // put in form destPort (localPort), from (destAddr), srcPort (destPort)
        String hash = "" + destPort + " " + from + " " + srcPort;
        TCPSock receiver = sockHash.get(hash);
        if (receiver == null) {
            // if no connection already made, search for a server listening at this port
            hash = "" + destPort;
            receiver = sockHash.get(hash);
            if (receiver == null) {
                // unable to find anything, return FIN
                try {
                    Transport tr = new Transport(destPort, srcPort, Transport.ACK, 1, t.getSeqNum(), dummy);
                    byte[] payload = tr.pack();
                    node.sendSegment(addr, from, Protocol.TRANSPORT_PKT, payload);
                } catch (Exception e) {
                    System.out.println("Error caught: " + e.getMessage());
                }
                return;
            }

        } if (receiver.isClosed()) {
            return;
        }

        int type = t.getType();
        // if SYN, add to receiver's synQ, UNLESS is already a server awaiting the client who missed an ACK
        if (type == Transport.SYN) {
            if (receiver.synQ == null) {    
            // NOT a listening socket, is most likely server ready to accept bc it
            // received the packet with the same addresses
                sendMsg(receiver.localPort, receiver.destAddr, receiver.destPort, Transport.ACK, receiver.windowSize, receiver.acked, receiver); 
                return;
            }
            System.out.print("S");
            int seq = tSeqNum;
            receiver.addSynQ("" + from + " " + srcPort + " " + seq);
            return;
        }

        // if ACK, check what type of ACK
        else if (type == Transport.ACK) {

            // if for connection, establish
            if (receiver.isConnectionPending()) {
                receiver.seqNum = tSeqNum;
                receiver.acked = tSeqNum;
                receiver.connectSock();
                PacketTime pt = receiver.unacked.remove();
                receiver.updateTimeout(manager.now() - pt.startTime);
                return;
            }

            // if for packet, update acked if is an in-order ACK received
            else if (receiver.isConnected() || receiver.isClosurePending()) {
                // track server's open buffer space
                receiver.reportedWindowSize = t.getWindow() + 1;

                if (tSeqNum > receiver.acked) {
                    System.out.print(":");
                    receiver.prevAck = tSeqNum;
                    
                    while (receiver.acked < tSeqNum) {
                        PacketTime pt = receiver.unacked.remove();
                        Transport rem = pt.packet;
                        int length = rem.getPayload().length;
                        receiver.acked += length;
                        receiver.updateTimeout(manager.now() - pt.startTime);

                        if (receiver.incrWin >= receiver.windowSize) {

                            receiver.windowSize += 107;
                            receiver.incrWin = 0;
                        }
                        else {
                            receiver.incrWin += 107;
                        }
                    }
                }

                // if ACK is for less than or equal to seqNum, then still need that packet, but don't change window size
                else if (tSeqNum != receiver.finSeq) { 
                    int win;

                    if (tSeqNum == receiver.prevAck) {
                        // if same ACK received 3 times in a row, half the window size
                        if (receiver.ackRep >= 2) {
                            win = receiver.windowSize / 2;
                            receiver.resend(tSeqNum);
                        }
                        else {
                            receiver.ackRep += 1;
                            win = receiver.windowSize;
                        }
                    }
                    // else keep it the same
                    else 
                        win = receiver.windowSize;
                    
                    receiver.windowSize = win;
                }

                // received the FIN's ACK!
                else { 
                    receiver.close();
                    return;
                }
                
                // if all data is written and resent reliably, and if in SHUTDOWN, send FIN
                if (receiver.isClosurePending() && receiver.unacked.size() == 0) {
                    sendMsg(receiver.localPort, receiver.destAddr, receiver.destPort, Transport.FIN, receiver.windowSize, receiver.acked, receiver);
                    receiver.finSeq = receiver.acked;
                }

                return;
            }
        }

        // if DATA, check connection, then check seqNum, then add to TCPSock buffer
        else if (type == Transport.DATA) {
            if (receiver.isConnected()) {
                // if is the next packet asked for, add to TCPSock buffer if there is space and ACK
                if (tSeqNum == receiver.acked) {
                    System.out.print(".");
                    try {
                        // check if buffer has enough space
                        if (t.getPayload().length <= (receiver.buffer.capacity() - receiver.buffer.position())) {
                            receiver.buffer.put(t.getPayload());
                            receiver.acked += t.getPayload().length;
                            System.out.print(":");
                            int winSize = receiver.buffer.capacity() - receiver.buffer.position();
                            sendMsg(receiver.localPort, receiver.destAddr, receiver.destPort, Transport.ACK, winSize, receiver.acked, receiver);
                        }
                    }
                    catch (Exception e) {
                        System.out.println("Exception caught: " + e.getMessage());
                    }
                    return;
                }
                // if is less than the packet asked for, resend ACK
                else if (tSeqNum < receiver.acked) {
                    System.out.print("?");
                    int winSize = (receiver.buffer.capacity() - receiver.buffer.position());
                    sendMsg(receiver.localPort, receiver.destAddr, receiver.destPort, Transport.ACK, winSize, receiver.acked, receiver);
                    return;
                }
            }
            else {
                return;
            }
        }

        // if type == Transport.FIN
        else if (type == Transport.FIN){ 
            
            // receiver is connected
            if (receiver.isConnected()) {
                // only server will receive this
                // if is a listening socket, ignore it
                if (hash.equals("" + destPort)) {
                    sendMsg(receiver.localPort, from, srcPort, Transport.ACK, receiver.windowSize, tSeqNum, receiver);
                    return;
                }

                // if is server and is done reading, release
                else {
                    sendMsg(receiver.localPort, receiver.destAddr, receiver.destPort, Transport.ACK, receiver.windowSize, tSeqNum, receiver);
                    System.out.print("F");
                    receiver.close();
                }

                return;

            }

            // should never happen
            if (receiver.isClosurePending()) {
                System.out.print("F");
                sendMsg(receiver.localPort, from, srcPort, Transport.ACK, receiver.windowSize, tSeqNum, receiver);
                receiver.close();
                return;
            }
        }

        // received a HELO packet
        //FOR ALL THESE THINGS, HAVE DYING CHECKS !!!!!#)@#RQ#EI(UFW#($#PFE)IOFWOEPFJ#QWRF)
        else if (type == Transport.HELO){
            if (receiver.isServer &&  receiver.sslLib.isNew()) {
                receiver.sslLib.parseHelo(pay);
                receiver.state = TCPSock.State.HANDSHAKE;

            }
            else if (!receiver.isServer && receiver.sslLib.isHelo()) {
                receiver.sslLib.parseHelo(pay);
                receiver.sslLib.setCert();
            }
            else {
                System.out.println("WHAAAT?? Redundant helo ?!");
                
            }
            return;
        }

        else if (type == Transport.CERT){
            System.out.println("CERT received");
            if (!receiver.isServer &&  receiver.sslLib.isCert()) {
                if(!receiver.sslLib.parseCert(pay)) {
                    receiver.sslLib.die = true;
                    return;
                }
                if(receiver.sslLib.isCertDone) {
                    receiver.sslLib.setS_Done();
                }
            }
            else {
                System.out.println("WhaaaT?? Redundant cert ?!");
            }
            return;
        }

        else if (type == Transport.S_DONE){
            System.out.println("S_DONE received");
            if (!receiver.isServer && receiver.sslLib.isS_Done()) {
                receiver.sslLib.sendKey();
                receiver.sslLib.sendFinished();
                receiver.sslLib.setFinished();
            }
            else {
                System.out.println("WhaaaT?? Redundant s_done ?!");
            }
            return;
        }

        else if (type == Transport.C_KEYX){
            if (receiver.isServer && receiver.sslLib.isHelo()) {
                receiver.sslLib.parseKey(pay);
                receiver.sslLib.setC_Keyx();
            }
            else {
                System.out.println("WhaaaT?? Redundant c_keyx ?!");
            }
            return;
        }

        else if (type == Transport.FINISHED){
            if (receiver.isServer && receiver.sslLib.isC_Keyx()) {
                receiver.sslLib.parseFinished(pay);
                receiver.sslLib.sendFinished();
                receiver.sslLib.setFinished();
            }
            else if (!receiver.isServer && receiver.sslLib.isHelo()) {
                receiver.sslLib.parseFinished(pay);
                receiver.sslLib.setDone();
            }
            else {
                System.out.println("WhaaaT?? Redundant c_keyx ?!");
            }
            return;
        }

        else if (type == Transport.ALERT){
            return;
        }

        return;

    }

    // TCP Message sending - for SYN, ACK, and FIN
    public int sendMsg(int localPort, int destAddr, int destPort, int type, int window, int seqNum, TCPSock sender) {
        Transport t;
        try {
            t = new Transport(localPort, destPort, type, window, seqNum, dummy);
            byte[] payload = t.pack();
            node.sendSegment(addr, destAddr, Protocol.TRANSPORT_PKT, payload);
        } catch (Exception e) {
            System.out.println("Error caught: " + e.getMessage());
            return -1;
        }

        // timeout for SYNs and FINs
        if (type == Transport.SYN || type == Transport.FIN) {

            node.addTimer(sender.calcTimeout(), "resend", sender, seqNum);
            PacketTime pt = new PacketTime(t, manager.now());
            sender.unacked.add(pt);

            if (type == Transport.SYN)  
                sender.acked = seqNum;
        }
        return 0;
    }

    // TCP packet sending, returns -1 for failure, # of packets written for success
    // sets a timer and increases the timer count
    public int sendPkt(int destAddr, PacketTime pt, TCPSock sender, int n) {
        
        System.out.print(".");
        node.sendSegment(addr, destAddr, Protocol.TRANSPORT_PKT, pt.packet.pack());
        node.addTimer(sender.calcTimeout(), "resend", sender, n);
        sender.seqNum += pt.packet.getPayload().length;
        sender.unacked.add(pt);
    
        return 1;

    }

    public void releaseSock(int port) {
        sockArr[port] = false;
    }

    public void removeSock(String hash) {
        sockHash.remove(hash);
    }


    /*
     * End Socket API
     */
}
