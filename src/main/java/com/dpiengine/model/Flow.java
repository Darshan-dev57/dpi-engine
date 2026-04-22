package com.dpiengine.model;

/**
 * Tracks the state of a single network flow (connection).
 *
 * A flow is identified by its FiveTuple. For every new five-tuple seen
 * in the PCAP, the DPI engine creates one Flow object and updates it
 * as subsequent packets of the same connection arrive.
 */
public class Flow {

    public final FiveTuple tuple;

    /** Classified application (YouTube, Netflix, DNS, HTTP, …) */
    public AppType appType = AppType.UNKNOWN;

    /**
     * Server Name Indication — the hostname extracted from:
     *   - TLS Client Hello (for HTTPS traffic), OR
     *   - HTTP Host header (for plain HTTP traffic)
     *
     * This is the "secret weapon" of DPI: even though HTTPS encrypts the
     * content, the domain name is sent in plaintext in the first packet.
     */
    public String sni = "";

    public long packetCount = 0;
    public long byteCount   = 0;
    public boolean blocked  = false;

    public Flow(FiveTuple tuple) {
        this.tuple = tuple;
    }

    @Override
    public String toString() {
        return String.format("Flow[%s | app=%s | sni=%s | pkts=%d | bytes=%d | blocked=%b]",
                tuple, appType.displayName(), sni.isEmpty() ? "-" : sni,
                packetCount, byteCount, blocked);
    }
}