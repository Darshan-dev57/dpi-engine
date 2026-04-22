package com.dpiengine.parser;

import com.dpiengine.model.RawPacket;

import java.io.BufferedInputStream;
import java.io.Closeable;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Minimal binary PCAP reader for classic libpcap files.
 * Supports little-endian and big-endian captures.
 */
public class PcapReader implements Closeable {

    private InputStream in;
    private boolean littleEndian = true;
    public byte[] globalHeaderBytes;

    public void open(String filename) throws IOException {
        in = new BufferedInputStream(new FileInputStream(filename));
        globalHeaderBytes = readFully(24);
        if (globalHeaderBytes == null) {
            throw new IOException("Invalid PCAP: missing 24-byte global header");
        }

        int b0 = globalHeaderBytes[0] & 0xFF;
        int b1 = globalHeaderBytes[1] & 0xFF;
        int b2 = globalHeaderBytes[2] & 0xFF;
        int b3 = globalHeaderBytes[3] & 0xFF;

        if (b0 == 0xD4 && b1 == 0xC3 && b2 == 0xB2 && b3 == 0xA1) {
            littleEndian = true;
        } else if (b0 == 0xA1 && b1 == 0xB2 && b2 == 0xC3 && b3 == 0xD4) {
            littleEndian = false;
        } else {
            throw new IOException("Unsupported PCAP magic number");
        }
    }

    public RawPacket readNext() throws IOException {
        byte[] hdr = readFully(16);
        if (hdr == null) {
            return null;
        }

        RawPacket pkt = new RawPacket();
        pkt.tsSec = readUint32(hdr, 0);
        pkt.tsUsec = readUint32(hdr, 4);
        pkt.inclLen = (int) readUint32(hdr, 8);
        pkt.origLen = (int) readUint32(hdr, 12);

        if (pkt.inclLen < 0 || pkt.inclLen > 10_000_000) {
            throw new IOException("Invalid packet incl_len: " + pkt.inclLen);
        }

        byte[] data = readFully(pkt.inclLen);
        if (data == null) {
            return null;
        }
        pkt.data = data;
        return pkt;
    }

    private long readUint32(byte[] data, int offset) {
        if (littleEndian) {
            return ((long) (data[offset] & 0xFF))
                    | (((long) (data[offset + 1] & 0xFF)) << 8)
                    | (((long) (data[offset + 2] & 0xFF)) << 16)
                    | (((long) (data[offset + 3] & 0xFF)) << 24);
        }

        return (((long) (data[offset] & 0xFF)) << 24)
                | (((long) (data[offset + 1] & 0xFF)) << 16)
                | (((long) (data[offset + 2] & 0xFF)) << 8)
                | ((long) (data[offset + 3] & 0xFF));
    }

    private byte[] readFully(int len) throws IOException {
        byte[] buf = new byte[len];
        int off = 0;
        while (off < len) {
            int r = in.read(buf, off, len - off);
            if (r < 0) {
                if (off == 0) return null;
                throw new IOException("Unexpected EOF while reading PCAP");
            }
            off += r;
        }
        return buf;
    }

    @Override
    public void close() throws IOException {
        if (in != null) in.close();
    }
}