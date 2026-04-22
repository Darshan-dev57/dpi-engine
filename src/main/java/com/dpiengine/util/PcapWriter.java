package com.dpiengine.util;

import com.dpiengine.model.RawPacket;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Writes packets to a PCAP output file.
 * Re-uses the global header from the input file so Wireshark can open the output.
 */
public class PcapWriter implements Closeable {

    private OutputStream out;

    /**
     * Open the output file and write the global header copied from the input.
     *
     * @param filename         output path
     * @param globalHeaderBytes the 24 raw bytes from the input PCAP's global header
     */
    public void open(String filename, byte[] globalHeaderBytes) throws IOException {
        out = new BufferedOutputStream(new FileOutputStream(filename));
        out.write(globalHeaderBytes);
    }

    /**
     * Write a single packet (header + data) to the output file.
     * The packet header is always written in little-endian (most common PCAP format).
     */
    public void writePacket(RawPacket pkt) throws IOException {
        // Build 16-byte packet record header
        ByteBuffer hdr = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        hdr.putInt((int)(pkt.tsSec  & 0xFFFFFFFFL));
        hdr.putInt((int)(pkt.tsUsec & 0xFFFFFFFFL));
        hdr.putInt(pkt.data.length);
        hdr.putInt(pkt.origLen);
        out.write(hdr.array());
        out.write(pkt.data);
    }

    @Override
    public void close() throws IOException {
        if (out != null) out.close();
    }
}