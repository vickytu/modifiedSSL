/* 
 * Wrapper class for keeping track of round trip time of packets
 * used in queue of packets not yet acknowledged
 *
 */

import java.util.*;

public class PacketTime {

	public Transport packet;
	public long startTime;

	public PacketTime(Transport t, long time) {
		this.packet = t;
		this.startTime = time;
	}

}