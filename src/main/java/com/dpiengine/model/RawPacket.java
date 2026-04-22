package com.dpiengine.model;

/**
 * A raw packet as read from the PCAP file.
 *
 * Structure of a PCAP packet record:
 *   [ts_sec: 4 bytes][ts_usec: 4 bytes][incl_len: 4 bytes][orig_len: 4 bytes]
 *   [packet data: incl_len bytes]
 */
public class RawPacket {
    public long tsSec;    // timestamp seconds
    public long tsUsec;   // timestamp microseconds
    public int  inclLen;  // captured length
    public int  origLen;  // original length on wire
    public byte[] data;   // the actual packet bytes
}