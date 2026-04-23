package com.dpiengine;

import com.dpiengine.engine.BlockingRules;
import com.dpiengine.engine.DpiEngine;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class Main {
    public static void main(String[] args) {
        if (args.length < 2) {
            printUsage();
            return;
        }

        String inputFile = args[0];
        String outputFile = args[1];

        BlockingRules rules = new BlockingRules();
        List<String> parseErrors = new ArrayList<>();

        for (int i = 2; i < args.length; i++) {
            String arg = args[i];

            if (arg.startsWith("--block-ip=")) {
                String ip = arg.substring("--block-ip=".length()).trim();
                if (ip.isEmpty()) {
                    parseErrors.add("Empty value for --block-ip");
                } else {
                    rules.blockIp(ip);
                }
            } else if ("--block-ip".equals(arg)) {
                if (i + 1 < args.length) {
                    rules.blockIp(args[++i]);
                } else {
                    parseErrors.add("--block-ip requires an argument");
                }
            } else if (arg.startsWith("--block-app=")) {
                String app = arg.substring("--block-app=".length()).trim();
                if (app.isEmpty()) {
                    parseErrors.add("Empty value for --block-app");
                } else {
                    rules.blockApp(app);
                }
            } else if ("--block-app".equals(arg)) {
                if (i + 1 < args.length) {
                    rules.blockApp(args[++i]);
                } else {
                    parseErrors.add("--block-app requires an argument");
                }
            } else if (arg.startsWith("--block-domain=")) {
                String domain = arg.substring("--block-domain=".length()).trim();
                if (domain.isEmpty()) {
                    parseErrors.add("Empty value for --block-domain");
                } else {
                    rules.blockDomain(domain);
                }
            } else if ("--block-domain".equals(arg)) {
                if (i + 1 < args.length) {
                    rules.blockDomain(args[++i]);
                } else {
                    parseErrors.add("--block-domain requires an argument");
                }
            } else if ("--help".equals(arg) || "-h".equals(arg)) {
                printUsage();
                return;
            } else {
                parseErrors.add("Unknown argument: " + arg);
            }
        }

        if (!parseErrors.isEmpty()) {
            for (String error : parseErrors) {
                System.err.println("[CLI] " + error);
            }
            System.err.println();
            printUsage();
            System.exit(1);
        }

        System.out.println();
        if (rules.hasRules()) {
            System.out.println("[DPI] Blocking rules configured.");
        } else {
            System.out.println("[DPI] No blocking rules -- running in analysis-only mode.");
        }

        DpiEngine engine = new DpiEngine(rules);
        try {
            engine.process(inputFile, outputFile);
        } catch (IOException e) {
            System.err.println("\n[ERROR] " + e.getMessage());
            System.exit(1);
        }
    }

    private static void printUsage() {
        System.out.println();
        System.out.println("+----------------------------------------------------------+");
        System.out.println("|    DPI Engine - Deep Packet Inspection (Java Edition)    |");
        System.out.println("+----------------------------------------------------------+");
        System.out.println();
        System.out.println("Usage:  java -jar dpi-engine-1.0.0-jar-with-dependencies.jar <input.pcap> <output.pcap> [options]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --block-ip <ip> / --block-ip=<ip>        Block traffic by source IP");
        System.out.println("  --block-app <app> / --block-app=<app>    Block traffic by app (e.g. YOUTUBE, NETFLIX)");
        System.out.println("  --block-domain <dom> / --block-domain=<dom>  Block traffic by domain/SNI substring");
        System.out.println("  --help, -h                Show this help");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  java -jar dpi-engine-1.0.0-jar-with-dependencies.jar capture.pcap out.pcap");
        System.out.println("  java -jar dpi-engine-1.0.0-jar-with-dependencies.jar capture.pcap out.pcap --block-app YOUTUBE");
        System.out.println("  java -jar dpi-engine-1.0.0-jar-with-dependencies.jar capture.pcap out.pcap --block-domain facebook");
        System.out.println();
    }
}