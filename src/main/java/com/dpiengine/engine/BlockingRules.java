package com.dpiengine.engine;

import com.dpiengine.model.AppType;
import com.dpiengine.model.FiveTuple;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Manages traffic blocking rules.
 *
 * Three rule types (matching the original C++ BlockingRules class):
 *   1. Block by source IP   — drop all traffic from a specific host
 *   2. Block by AppType     — drop all traffic classified as a specific app
 *   3. Block by domain      — drop traffic whose SNI/Host contains a substring
 */
public class BlockingRules {

    private final Set<Integer> blockedIps     = new HashSet<>();
    private final Set<AppType> blockedApps    = new HashSet<>();
    private final List<String> blockedDomains = new ArrayList<>();

    public void blockIp(String ip) {
        blockedIps.add(FiveTuple.ipToInt(ip));
        System.out.println("[Rules] Blocked IP: " + ip);
    }

    public void blockApp(String appName) {
        try {
            AppType type = AppType.valueOf(appName.toUpperCase());
            blockedApps.add(type);
            System.out.println("[Rules] Blocked app: " + appName);
        } catch (IllegalArgumentException e) {
            System.err.println("[Rules] Unknown app type: " + appName
                    + "  (valid values: " + validApps() + ")");
        }
    }

    public void blockDomain(String domain) {
        blockedDomains.add(domain.toLowerCase());
        System.out.println("[Rules] Blocked domain: " + domain);
    }

    /**
     * Return true if this flow should be blocked.
     *
     * @param srcIp  raw int form of source IP
     * @param app    classified app type
     * @param sni    extracted SNI or HTTP Host (empty string if none)
     */
    public boolean isBlocked(int srcIp, AppType app, String sni) {
        if (blockedIps.contains(srcIp)) return true;
        if (blockedApps.contains(app))  return true;
        String lowerSni = sni.toLowerCase();
        for (String dom : blockedDomains) {
            if (lowerSni.contains(dom)) return true;
        }
        return false;
    }

    public boolean hasRules() {
        return !blockedIps.isEmpty() || !blockedApps.isEmpty() || !blockedDomains.isEmpty();
    }

    private String validApps() {
        StringBuilder sb = new StringBuilder();
        for (AppType t : AppType.values()) {
            if (t != AppType.UNKNOWN) sb.append(t.name()).append(", ");
        }
        return sb.toString();
    }
}