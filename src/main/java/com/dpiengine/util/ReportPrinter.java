package com.dpiengine.util;

import com.dpiengine.model.AppType;
import com.dpiengine.model.Flow;
import com.dpiengine.model.FiveTuple;

import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

public class ReportPrinter {
    public static void print(long total, long forwarded, long dropped,
                 Map<FiveTuple, Flow> flowTable,
                 Map<AppType, Long> appStats) {
    System.out.println();
    System.out.println("╔══════════════════════════════════════════════════════════╗");
    System.out.println("║                    PROCESSING REPORT                     ║");
    System.out.println("╠══════════════════════════════════════════════════════════╣");
    System.out.printf( "║  Total Packets  : %10d                             ║%n", total);
    System.out.printf( "║  Forwarded      : %10d                             ║%n", forwarded);
    System.out.printf( "║  Dropped        : %10d                             ║%n", dropped);
    System.out.printf( "║  Active Flows   : %10d                             ║%n", flowTable.size());
    System.out.println("╠══════════════════════════════════════════════════════════╣");
    System.out.println("║                  APPLICATION BREAKDOWN                   ║");
    System.out.println("╠══════════════════════════════════════════════════════════╣");

    List<Map.Entry<AppType, Long>> sorted = appStats.entrySet().stream()
        .sorted(Map.Entry.<AppType, Long>comparingByValue().reversed())
        .collect(Collectors.toList());

    for (Map.Entry<AppType, Long> entry : sorted) {
        double pct = total > 0 ? 100.0 * entry.getValue() / total : 0;
        int barLen = (int) (pct / 5);
        String bar = "#".repeat(Math.max(0, Math.min(barLen, 12)));
        System.out.printf("║  %-14s %8d  %5.1f%%  %-13s        ║%n",
            entry.getKey().displayName(),
            entry.getValue(), pct, bar);
    }
    System.out.println("╚══════════════════════════════════════════════════════════╝");

    System.out.println("\n[Detected Applications / Domains]");
    flowTable.values().stream()
        .filter(f -> !f.sni.isEmpty())
        .collect(Collectors.toMap(
            f -> f.sni,
            f -> f.appType,
            (a, b) -> a,
            TreeMap::new
        ))
        .forEach((sni, app) ->
            System.out.printf("  %-45s  →  %s%n", sni, app.displayName()));
    }
}