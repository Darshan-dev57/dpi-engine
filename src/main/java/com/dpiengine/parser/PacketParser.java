package com.dpiengine.parser;

import com.dpiengine.model.ParsedPacket;
import com.dpiengine.model.RawPacket;

/**
 * Parses raw packet bytes through the protocol stack:
 *   Ethernet (Layer 2) → IPv4 (Layer 3) → TCP / UDP (Layer 4)
 *
 * Networking Refresher
 * =====================
 * Every packet is a "nesting doll" of headers:
 *
 *  ┌───────────────────────────────────────────────────────┐
 *  │ Ethernet Header  (14 bytes)                           │
 *  │  ├ Dst MAC  [0-5]                                     │
 *  │  ├ Src MAC  [6-11]                                    │
 *  │  └ EtherType [12-13]  0x0800=IPv4                     │
 *  │ ┌─────────────────────────────────────────────────┐   │
 *  │ │ IPv4 Header (20+ bytes)                         │   │
 *  │ │  ├ Version+IHL [0]                              │   │
 *  │ │  ├ TTL         [8]                              │   │
 *  │ │  ├ Protocol    [9]  6=TCP, 17=UDP               │   │
 *  │ │  ├ Src IP      [12-15]                          │   │
 *  │ │  └ Dst IP      [16-19]                          │   │
 *  │ │ ┌───────────────────────────────────────────┐   │   │
 *  │ │ │ TCP Header (20+ bytes)                    │   │   │
 *  │ │ │  ├ Src Port  [0-1]                        │   │   │
 *  │ │ │  ├ Dst Port  [2-3]                        │   │   │
 *  │ │ │  ├ Seq Num   [4-7]                        │   │   │
 *  │ │ │  ├ Ack Num   [8-11]                       │   │   │
 *  │ │ │  ├ DataOffset[12] upper nibble            │   │   │
 *  │ │ │  └ Flags     [13]                         │   │   │
 *  │ │ │ ┌───────────────────────────────────────┐ │   │   │
 *  │ │ │ │ Application Payload (TLS, HTTP, DNS…) │ │   │   │
 *  │ │ │ └───────────────────────────────────────┘ │   │   │
 *  │ │ └───────────────────────────────────────────┘   │   │
 *  │ └─────────────────────────────────────────────────┘   │
 *  └───────────────────────────────────────────────────────┘
 */
public class PacketParser {

    private static final int ETHERTYPE_IPV4 = 0x0800;
    private static final int PROTO_TCP      = 6;
    private static final int PROTO_UDP      = 17;

    /**
     * Parse a raw packet into its constituent protocol fields.
     *
     * @param raw the raw PCAP packet
     * @param out the ParsedPacket to fill in
     * @return true if parsing succeeded at least through the IP layer
     */
    public static boolean parse(RawPacket raw, ParsedPacket out) {
        byte[] d = raw.data;
        out.timestampSec  = raw.tsSec;
        out.timestampUsec = raw.tsUsec;

        int offset = 0;

        // ── Ethernet Header ────────────────────────────────────────────────
        if (d.length < 14) return false;

        out.dstMac    = macToString(d, 0);
        out.srcMac    = macToString(d, 6);
        out.etherType = readUint16BE(d, 12);
        offset = 14;

        if (out.etherType != ETHERTYPE_IPV4) return false; // skip non-IPv4

        // ── IPv4 Header ─────────────────────────────────────────────────────
        if (d.length < offset + 20) return false;

        int versionIhl   = d[offset] & 0xFF;
        out.ipVersion    = (versionIhl >> 4) & 0x0F;
        int ihl          = versionIhl & 0x0F;        // header length in 32-bit words
        int ipHeaderLen  = ihl * 4;                  // convert to bytes

        if (out.ipVersion != 4 || ipHeaderLen < 20) return false;
        if (d.length < offset + ipHeaderLen) return false;

        out.ttl      = d[offset + 8] & 0xFF;
        out.protocol = d[offset + 9] & 0xFF;

        // IPs are 4 bytes each, starting at offset+12 and offset+16
        // They arrive in big-endian (network) order
        out.srcIp = ipBytesToString(d, offset + 12);
        out.dstIp = ipBytesToString(d, offset + 16);
        out.hasIp = true;
        offset += ipHeaderLen;

        // ── Transport Layer ─────────────────────────────────────────────────
        if (out.protocol == PROTO_TCP) {
            if (d.length < offset + 20) return true; // IP OK, TCP truncated
            out.srcPort  = readUint16BE(d, offset);
            out.dstPort  = readUint16BE(d, offset + 2);
            out.seqNumber = (int) readUint32BE(d, offset + 4);
            out.ackNumber = (int) readUint32BE(d, offset + 8);
            int dataOffset = (d[offset + 12] >> 4) & 0x0F; // TCP header length in 32-bit words
            int tcpHeaderLen = dataOffset * 4;
            out.tcpFlags = d[offset + 13] & 0xFF;
            if (tcpHeaderLen < 20 || d.length < offset + tcpHeaderLen) return true;
            out.hasTcp = true;
            out.payloadOffset = offset + tcpHeaderLen;
            out.payloadLength = d.length - out.payloadOffset;

        } else if (out.protocol == PROTO_UDP) {
            if (d.length < offset + 8) return true;
            out.srcPort = readUint16BE(d, offset);
            out.dstPort = readUint16BE(d, offset + 2);
            out.hasUdp  = true;
            out.payloadOffset = offset + 8;
            out.payloadLength = d.length - out.payloadOffset;
        }

        return true;
    }

    // ── Byte-reading helpers ────────────────────────────────────────────────

    /** Read a big-endian unsigned 16-bit integer */
    public static int readUint16BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    /** Read a big-endian unsigned 32-bit integer */
    public static long readUint32BE(byte[] data, int offset) {
        return (((long)(data[offset]     & 0xFF)) << 24)
             | (((long)(data[offset + 1] & 0xFF)) << 16)
             | (((long)(data[offset + 2] & 0xFF)) << 8)
             |  ((long)(data[offset + 3] & 0xFF));
    }

    /** Read a big-endian 24-bit integer (used for TLS record lengths) */
    public static int readUint24BE(byte[] data, int offset) {
        return ((data[offset]     & 0xFF) << 16)
             | ((data[offset + 1] & 0xFF) << 8)
             |  (data[offset + 2] & 0xFF);
    }

    /** Convert 4 bytes at offset to "a.b.c.d" string */
    private static String ipBytesToString(byte[] data, int offset) {
        return String.format("%d.%d.%d.%d",
                data[offset]     & 0xFF,
                data[offset + 1] & 0xFF,
                data[offset + 2] & 0xFF,
                data[offset + 3] & 0xFF);
    }

    /** Convert 6 bytes at offset to "aa:bb:cc:dd:ee:ff" */
    private static String macToString(byte[] data, int offset) {
        return String.format("%02x:%02x:%02x:%02x:%02x:%02x",
                data[offset]     & 0xFF,
                data[offset + 1] & 0xFF,
                data[offset + 2] & 0xFF,
                data[offset + 3] & 0xFF,
                data[offset + 4] & 0xFF,
                data[offset + 5] & 0xFF);
    }
}