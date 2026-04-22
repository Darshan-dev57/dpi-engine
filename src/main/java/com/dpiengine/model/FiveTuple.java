package com.dpiengine.model;

import java.util.Objects;

/**
 * Five-Tuple: the 5 fields that uniquely identify a TCP/UDP connection (flow).
 *
 * Concept: Every network conversation between two applications is uniquely
 * identified by: source IP, destination IP, source port, destination port,
 * and the transport protocol (TCP=6, UDP=17).
 *
 * All packets sharing the same five-tuple belong to the same "flow" and
 * are processed together by the DPI engine.
 */
public final class FiveTuple {

    public final int srcIp;    // stored as raw int (network byte order)
    public final int dstIp;
    public final int srcPort;
    public final int dstPort;
    public final int protocol; // 6 = TCP, 17 = UDP

    public FiveTuple(int srcIp, int dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp    = srcIp;
        this.dstIp    = dstIp;
        this.srcPort  = srcPort;
        this.dstPort  = dstPort;
        this.protocol = protocol;
    }

    /** Returns the reverse flow (swap src/dst) — used for bidirectional matching */
    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FiveTuple t)) return false;
        return srcIp == t.srcIp && dstIp == t.dstIp
                && srcPort == t.srcPort && dstPort == t.dstPort
                && protocol == t.protocol;
    }

    @Override
    public int hashCode() {
        return Objects.hash(srcIp, dstIp, srcPort, dstPort, protocol);
    }

    @Override
    public String toString() {
        return String.format("%s:%d -> %s:%d (%s)",
                intToIp(srcIp), srcPort,
                intToIp(dstIp), dstPort,
                protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?" + protocol);
    }

    /** Convert a packed int (network byte order) to "a.b.c.d" */
    public static String intToIp(int ip) {
        return String.format("%d.%d.%d.%d",
                (ip)        & 0xFF,
                (ip >>> 8)  & 0xFF,
                (ip >>> 16) & 0xFF,
                (ip >>> 24) & 0xFF);
    }

    /** Parse "a.b.c.d" to packed int (network byte order) */
    public static int ipToInt(String ip) {
        String[] parts = ip.split("\\.");
        int result = 0;
        for (int i = 0; i < 4; i++) {
            result |= (Integer.parseInt(parts[i]) & 0xFF) << (i * 8);
        }
        return result;
    }
}