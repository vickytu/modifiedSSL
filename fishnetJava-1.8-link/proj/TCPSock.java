/**
 * <p>Title: CPSC 433/533 Programming Assignment</p>
 *
 * <p>Description: Fishnet socket implementation</p>
 *
 * <p>Copyright: Copyright (c) 2006</p>
 *
 * <p>Company: Yale University</p>
 *
 * @author Hao Wang
 * @version 1.0
 */
import java.util.*;
import java.nio.ByteBuffer;

public class TCPSock {
    // TCP socket states
    enum State {
        // protocol states
        NEW,
        CLOSED,
        LISTEN,
        SYN_SENT,
        ESTABLISHED,
        HANDSHAKE,
        SHUTDOWN // close requested, FIN not sent (due to unsent data in queue) 
    }

    public static final int BUFFER_SIZE = 100000;

    public State state;
    public TCPManager tcpMan;
    // queue of things attempting to SYN, if is in listening state
    public ArrayDeque<String> synQ;
    // private int syncQcount; // can just use synQ.size right ???
    private int backlog;
    // make a buffer that stores info (maybe 2 pointers - for ack and transmission)
    public ByteBuffer buffer;
    public LinkedList<PacketTime> unacked;
    public int acked; // next packet either waiting for an ack or to be read
    public int seqNum; // packet number last sent or acknowledged
    public int localPort;
    public int destAddr;
    public int destPort;
    public int windowSize;
    public int reportedWindowSize;
    public int finSeq;
    public int prevAck;
    public int ackRep;
    private long totalRTT;
    private long devRTT;
    public int numPkts;
    public int incrWin;

    public SSLlib sslLib;
    public boolean isServer;



    public TCPSock(TCPManager tcpMan) {
        this.tcpMan = tcpMan;
        seqNum = 0;
        acked = 1;
        prevAck = 1;
        ackRep = 0;
        windowSize = 107;
        totalRTT = 1000;
        devRTT = 0;
        numPkts = 0;
        reportedWindowSize = 107;
        incrWin = 0;
        unacked = new LinkedList<PacketTime>();
        finSeq = -1;
        sslLib = new SSLlib(this, tcpMan);
        try {
            buffer = ByteBuffer.allocate(BUFFER_SIZE);
        } catch (Exception e) {
            System.out.println("TCPSock creation Exception caught: " + e.getMessage());
        }
    }

    /*
     * The following are the socket APIs of TCP transport service.
     * All APIs are NON-BLOCKING.
     */

    /**
     * Bind a socket to a local port
     *
     * @param localPort int local port number to bind the socket to
     * @return int 0 on success, -1 otherwise
     */
    public int bind(int localPort) {
        this.localPort = localPort;
        // check whether or not this port is free, and reserve if it is
        int free = tcpMan.reservePort(localPort);
        state = State.NEW;
        return free;
    }

    /**
     * Listen for connections on a socket
     * @param backlog int Maximum number of pending connections
     * @return int 0 on success, -1 otherwise
     */
    public int listen(int backlog) {
        // check state before -- has to be NEW
        if (state == State.NEW)
            state = State.LISTEN;
        else
            return -1;
        synQ = new ArrayDeque();
        //synQcount = 0;
        this.backlog = backlog;
        String lp = Integer.toString(localPort);
        int res = tcpMan.addSock(this, lp);
        return res;
    }

    /**
     * Accept a connection on a socket
     *
     * @return TCPSock The first established connection on the request queue
     */
    public TCPSock accept() {
        if (state != State.LISTEN)
            return null;
        // if queue empty, return null
        if (synQ.size() == 0)
            return null;

        // create new socket with all three key values
        TCPSock sock = new TCPSock(this.tcpMan);
        sock.bind(localPort);
        String dest = synQ.remove();
        String[] split = dest.split(" ");
        sock.destAddr = Integer.parseInt(split[0]);
        sock.destPort = Integer.parseInt(split[1]);
        sock.acked = Integer.parseInt(split[2]) + 1;
        String hash = Integer.toString(localPort) + " " + sock.destAddr + " " + sock.destPort;
        int res = sock.tcpMan.addSock(sock, hash);
        if (res == -1) 
            return null;

        // have TCPMan send ACK
        System.out.print(":");
        tcpMan.sendMsg(localPort, sock.destAddr, sock.destPort, Transport.ACK, sock.windowSize, sock.acked, this);    
        sock.state = State.ESTABLISHED;
        return sock;
       
    }

    public boolean isConnectionPending() {
        return (state == State.SYN_SENT);
    }

    public boolean isClosed() {
        return (state == State.CLOSED);
    }

    public boolean isConnected() {
        return (state == State.ESTABLISHED || state == State.HANDSHAKE);
    }

    public void connectSock() {
        state = State.ESTABLISHED;
    }

    public boolean isClosurePending() {
        return (state == State.SHUTDOWN);
    }

    /**
     * Initiate connection to a remote socket
     *
     * @param destAddr int Destination node address
     * @param destPort int Destination port
     * @return int 0 on success, -1 otherwise
     */
    public int connect(int destAddr, int destPort) {
        if (state == State.ESTABLISHED)
            return 0;
        if (state != State.NEW)
            return -1;
        this.destAddr = destAddr;
        this.destPort = destPort;

        // hash to localport, destAddr, destPort values in hashmap
        String hash = Integer.toString(localPort) + " " + Integer.toString(destAddr) + " " + Integer.toString(destPort);
        int res = tcpMan.addSock(this, hash);
        if (res != -1) {
            // have TCPman send SYN
            Random rand = new Random();
            seqNum = rand.nextInt(100);
            System.out.print("S");
            tcpMan.sendMsg(localPort, destAddr, destPort, Transport.SYN, windowSize, seqNum, this);
            state = State.SYN_SENT;
        }
        return -1;
    }

    // add a pending connection to server's synQ using String of "destAddr destPort"
    public void addSynQ(String dest) {
        if (synQ.size() < backlog)
            synQ.add(dest);
    }

    /**
     * Initiate closure of a connection (graceful shutdown)
     */
    public void close() {
        if (state == State.CLOSED)
            return;
        if (state == State.SHUTDOWN) {
            state = State.CLOSED;
            return;
        }

        state = State.SHUTDOWN;
        // if in shutdown and has nothing more to write, then send FIN 
        if (unacked.size() == 0) {
            tcpMan.sendMsg(localPort, destAddr, destPort, Transport.FIN, windowSize, seqNum, this);
            finSeq = seqNum;
        }
    }

    /**
     * Release a connection immediately (abortive shutdown)
     */
    public void release() {
        // close everything
        if (state == State.CLOSED) {
            // is client, so remove it from the socket array in TCPMan
            tcpMan.releaseSock(localPort);
            return;
        }

        state = State.CLOSED;
        String hash = Integer.toString(localPort) + " " + destAddr + " " + destPort;
        tcpMan.removeSock(hash);
    }

    /**
     * Write to the socket up to len bytes from the buffer buf starting at
     * position pos.
     *
     * @param buf byte[] the buffer to write from
     * @param pos int starting position in buffer
     * @param len int number of bytes to write
     * @return int on success, the number of bytes written, which may be smaller
     *             than len; on failure, -1
     */
    public int write(byte[] buf, int pos, int len) {
        if (state == State.CLOSED)
            return -1;

        // check how much data we can send by comparing seqNum - acked
        if ((seqNum - acked) >= windowSize) {
            return 0;
        }
        else { // check for minimum of length desired written by client, max bytes sendable by window, buffer space in server)
            len = Math.min((windowSize - seqNum + acked), len);
            len = Math.min(reportedWindowSize, len);
        }

        int count = 0;
        while (count < len) {


            int toWrite = Math.min(Transport.MAX_PAYLOAD_SIZE, (len - count));
            byte[] bufWrite = Arrays.copyOfRange(buf, pos + count, pos + count + toWrite);
            Transport t;

            try {
                t = new Transport(localPort, destPort, Transport.DATA, windowSize, seqNum, bufWrite);
            } catch (Exception e) {
                System.out.println("Error caught: " + e.getMessage());
                return -1;
            }

            if (t != null) {
                System.out.print(".");
                PacketTime pt = new PacketTime(t, tcpMan.getMan().now());
                tcpMan.sendPkt(destAddr, pt, this, seqNum);
            }
            count += toWrite;
        }
        
        return count;
    }

    /**
     * Read from the socket up to len bytes into the buffer buf starting at
     * position pos.
     *
     * @param buf byte[] the buffer
     * @param pos int starting position in buffer
     * @param len int number of bytes to read
     * @return int on success, the number of bytes read, which may be smaller
     *             than len; on failure, -1
     */
    public int read(byte[] buf, int pos, int len) {
        if (state == State.CLOSED)
            return -1;
        
        buffer.flip();
        int toRead = Math.min(buffer.remaining(), len);

        try {
            buffer.get(buf, pos, toRead);
            buffer.compact();
        } catch (Exception e) {
            System.out.println("Exception caught: " + e.getMessage());
            return -1;
        } 
        
        // if is closure pending and done reading, release 
        if (state == State.SHUTDOWN) {
            if (buffer.position() == 0)
                release();
        }

        return toRead;
    }

    // use as callback method for timers
    public int resend (Integer n) {

        if (state == State.CLOSED) {
            return -1;
        }

        // if n < acked, know it is an old timeout, so ignore
        // if n > acked, know that we are already going to be resending it, so ignore
        if (n == acked) {
            // set seqNum to acked and then begin resending everything in the unacked queue
            seqNum = acked;
            int size = unacked.size();

            while (size > 0) {

                System.out.print("!");
                PacketTime pt = unacked.remove();


                if (pt != null) {
                    tcpMan.sendPkt(destAddr, pt, this, seqNum);
                }

                size -= 1;
            }

            totalRTT = totalRTT * 2;
            devRTT = 0;

            windowSize = 107;
        }
        // when this goes off, want to know if it has been 
        return 1;

    }

    public void updateTimeout(long sample) {

        totalRTT = (long)(0.875 * totalRTT) + (long)(0.125 * sample);
        devRTT = (long)(0.75 * devRTT) + (long)(0.25 * Math.abs(sample - totalRTT));


    }

    // method to find the ideal timeout time (average RTT + 5msec)
    public long calcTimeout() {

        return Math.min(3000, (totalRTT + 4*devRTT));

    }

    /*
     * End of socket API
     */
}
