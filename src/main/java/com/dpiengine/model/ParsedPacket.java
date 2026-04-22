package com.dpiengine.model;

/**
 * Result of parsing a raw packet through the full protocol stack:
 *   Ethernet → IPv4 → TCP/UDP
 *
 * The parser fills in these fields as it processes each layer.
 * If a layer is absent or malformed, the corresponding "has*" flag
 * stays false and the fields are left at their defaults.
 */
public class ParsedPacket {

    // ---- Ethernet Layer ----
    public String srcMac  = "";
    public String dstMac  = "";
    public int etherType  = 0;   // 0x0800 = IPv4

    // ---- IPv4 Layer ----
    public boolean hasIp  = false;
    public String srcIp   = "";
    public String dstIp   = "";
    public int protocol   = 0;   // 6=TCP, 17=UDP, 1=ICMP
    public int ttl        = 0;
    public int ipVersion  = 0;

    // ---- Transport Layer ----
    public boolean hasTcp = false;
    public boolean hasUdp = false;
    public int srcPort    = 0;
    public int dstPort    = 0;
    public int seqNumber  = 0;
    public int ackNumber  = 0;
    public int tcpFlags   = 0;   // SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04, PSH=0x08

    // ---- Payload ----
    /** Offset into RawPacket.data where the application payload starts */
    public int payloadOffset = 0;
    public int payloadLength = 0;

    // ---- Timestamps (from PCAP header) ----
    public long timestampSec  = 0;
    public long timestampUsec = 0;

    /** TCP flag helpers */
    public boolean isSyn() { return (tcpFlags & 0x02) != 0; }
    public boolean isAck() { return (tcpFlags & 0x10) != 0; }
    public boolean isFin() { return (tcpFlags & 0x01) != 0; }
    public boolean isRst() { return (tcpFlags & 0x04) != 0; }

    public String tcpFlagsString() {
        StringBuilder sb = new StringBuilder();
        if (isSyn()) sb.append("SYN ");
        if (isAck()) sb.append("ACK ");
        if (isFin()) sb.append("FIN ");
        if (isRst()) sb.append("RST ");
        if ((tcpFlags & 0x08) != 0) sb.append("PSH ");
        if ((tcpFlags & 0x20) != 0) sb.append("URG ");
        return sb.toString().trim().isEmpty() ? "none" : sb.toString().trim();
    }
}