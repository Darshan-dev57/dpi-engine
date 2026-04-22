package com.dpiengine.engine;

import com.dpiengine.extractor.HttpHostExtractor;
import com.dpiengine.extractor.SniExtractor;
import com.dpiengine.model.*;
import com.dpiengine.parser.PacketParser;
import com.dpiengine.parser.PcapReader;
import com.dpiengine.util.PcapWriter;
import com.dpiengine.util.ReportPrinter;

import java.io.IOException;
import java.util.*;

/**
 * Core DPI Engine.
 *
 * Processing pipeline for each packet:
 *   1. Read raw bytes from PCAP  (PcapReader)
 *   2. Parse protocol headers    (PacketParser: Eth → IP → TCP/UDP)
 *   3. Build / update flow entry (FiveTuple → Flow map)
 *   4. Extract application ID    (SNI / HTTP Host / DNS / port fallback)
 *   5. Evaluate blocking rules   (BlockingRules)
 *   6. Write allowed packets to output PCAP  (PcapWriter)
 *   7. Print statistics report   (ReportPrinter)
 */
public class DpiEngine {

    private final BlockingRules rules;

    // Flow table: maps each unique five-tuple to its tracked flow state
    private final Map<FiveTuple, Flow> flowTable = new HashMap<>();

    // Statistics
    private long totalPackets   = 0;
    private long forwardedCount = 0;
    private long droppedCount   = 0;
    private final Map<AppType, Long> appStats = new EnumMap<>(AppType.class);

    public DpiEngine(BlockingRules rules) {
        this.rules = rules;
    }

    /**
     * Process the input PCAP, write non-blocked packets to output PCAP.
     */
    public void process(String inputFile, String outputFile) throws IOException {
        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════════╗");
        System.out.println("║              DPI ENGINE v1.0  (Java Edition)             ║");
        System.out.println("╚══════════════════════════════════════════════════════════╝");
        System.out.println();
        System.out.println("[DPI] Opening input: " + inputFile);

        try (PcapReader reader = new PcapReader();
             PcapWriter writer = new PcapWriter()) {

            reader.open(inputFile);
            writer.open(outputFile, reader.globalHeaderBytes);

            System.out.println("[DPI] Processing packets...\n");

            RawPacket raw;
            ParsedPacket parsed = new ParsedPacket();

            while ((raw = reader.readNext()) != null) {
                totalPackets++;

                // Parse the packet
                if (!PacketParser.parse(raw, parsed)) continue;
                if (!parsed.hasIp) continue;
                if (!parsed.hasTcp && !parsed.hasUdp) continue;

                // Build the five-tuple key for this packet
                FiveTuple key = new FiveTuple(
                        FiveTuple.ipToInt(parsed.srcIp),
                        FiveTuple.ipToInt(parsed.dstIp),
                        parsed.srcPort,
                        parsed.dstPort,
                        parsed.protocol
                );

                // Get or create the flow for this connection
                Flow flow = flowTable.computeIfAbsent(key, Flow::new);
                flow.packetCount++;
                flow.byteCount += raw.data.length;

                // ── Application Identification ───────────────────────────
                classifyFlow(flow, parsed, raw);

                // ── Blocking Decision ────────────────────────────────────
                if (!flow.blocked) {
                    flow.blocked = rules.isBlocked(key.srcIp, flow.appType, flow.sni);
                    if (flow.blocked) {
                        System.out.printf("[BLOCKED] %s -> %s  app=%-12s  sni=%s%n",
                                parsed.srcIp, parsed.dstIp,
                                flow.appType.displayName(),
                                flow.sni.isEmpty() ? "-" : flow.sni);
                    }
                }

                // Update app statistics
                appStats.merge(flow.appType, 1L, Long::sum);

                // Forward or drop
                if (flow.blocked) {
                    droppedCount++;
                } else {
                    forwardedCount++;
                    writer.writePacket(raw);
                }
            }
        }

        // Print the final report
        ReportPrinter.print(totalPackets, forwardedCount, droppedCount,
                flowTable, appStats);

        System.out.println("\n[DPI] Output written to: " + outputFile);
    }

    // ── Private helpers ─────────────────────────────────────────────────────

    /**
     * Attempt to classify the flow's application type using:
     *   1. TLS SNI (for HTTPS on port 443)
     *   2. HTTP Host header (for HTTP on port 80)
     *   3. DNS port check (port 53)
     *   4. Port-based fallback
     */
    private void classifyFlow(Flow flow, ParsedPacket parsed, RawPacket raw) {
        // Only try to classify if we haven't found an SNI yet
        if (!flow.sni.isEmpty()) return;

        // --- TLS SNI (port 443, TCP) ---
        if (parsed.hasTcp && parsed.dstPort == 443
                && (flow.appType == AppType.UNKNOWN || flow.appType == AppType.HTTPS)) {

            SniExtractor.extract(raw.data, parsed.payloadOffset, parsed.payloadLength)
                    .ifPresent(sni -> {
                        flow.sni     = sni;
                        flow.appType = AppType.fromSni(sni);
                    });
        }

        // --- HTTP Host header (port 80, TCP) ---
        if (flow.sni.isEmpty() && parsed.hasTcp && parsed.dstPort == 80
                && (flow.appType == AppType.UNKNOWN || flow.appType == AppType.HTTP)) {

            HttpHostExtractor.extract(raw.data, parsed.payloadOffset, parsed.payloadLength)
                    .ifPresent(host -> {
                        flow.sni     = host;
                        flow.appType = AppType.fromSni(host);
                    });
        }

        // --- DNS (port 53, UDP or TCP) ---
        if (flow.appType == AppType.UNKNOWN
                && (parsed.dstPort == 53 || parsed.srcPort == 53)) {
            flow.appType = AppType.DNS;
        }

        // --- Port-based fallback ---
        if (flow.appType == AppType.UNKNOWN) {
            if (parsed.dstPort == 443) flow.appType = AppType.HTTPS;
            else if (parsed.dstPort == 80) flow.appType = AppType.HTTP;
        }
    }

    // Getters for testing / reporting
    public Map<FiveTuple, Flow> getFlowTable() { return Collections.unmodifiableMap(flowTable); }
    public long getTotalPackets()   { return totalPackets; }
    public long getForwardedCount() { return forwardedCount; }
    public long getDroppedCount()   { return droppedCount; }
}