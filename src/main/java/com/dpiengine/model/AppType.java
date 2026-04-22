package com.dpiengine.model;

/**
 * Application type classification.
 * Mirrors the C++ AppType enum — each constant represents a recognized
 * application or protocol that the DPI engine can identify.
 */
public enum AppType {
    UNKNOWN,
    HTTP,
    HTTPS,
    DNS,
    TLS,
    QUIC,
    GOOGLE,
    FACEBOOK,
    YOUTUBE,
    TWITTER,
    INSTAGRAM,
    NETFLIX,
    AMAZON,
    MICROSOFT,
    APPLE,
    WHATSAPP,
    TELEGRAM,
    TIKTOK,
    SPOTIFY,
    ZOOM,
    DISCORD,
    GITHUB,
    CLOUDFLARE;

    /**
     * Human-readable display name for the application type.
     */
    public String displayName() {
        return switch (this) {
            case TWITTER   -> "Twitter/X";
            case UNKNOWN   -> "Unknown";
            default        -> name().charAt(0) + name().substring(1).toLowerCase();
        };
    }

    /**
     * Maps an SNI hostname (or HTTP Host) to the matching AppType.
     * Uses substring matching — same logic as the C++ sniToAppType().
     *
     * @param sni the server name indication string (lowercase expected)
     * @return classified AppType
     */
    public static AppType fromSni(String sni) {
        if (sni == null || sni.isEmpty()) return UNKNOWN;
        String s = sni.toLowerCase();

        if (s.contains("youtube") || s.contains("ytimg") || s.contains("youtu.be"))
            return YOUTUBE;
        if (s.contains("google") || s.contains("gstatic") || s.contains("googleapis")
                || s.contains("ggpht") || s.contains("gvt1"))
            return GOOGLE;
        if (s.contains("instagram") || s.contains("cdninstagram"))
            return INSTAGRAM;
        if (s.contains("whatsapp") || s.contains("wa.me"))
            return WHATSAPP;
        if (s.contains("facebook") || s.contains("fbcdn") || s.contains("fb.com")
                || s.contains("fbsbx") || s.contains("meta.com"))
            return FACEBOOK;
        if (s.contains("twitter") || s.contains("twimg") || s.contains("x.com") || s.contains("t.co"))
            return TWITTER;
        if (s.contains("netflix") || s.contains("nflxvideo") || s.contains("nflximg"))
            return NETFLIX;
        if (s.contains("amazon") || s.contains("amazonaws") || s.contains("cloudfront") || s.contains("aws"))
            return AMAZON;
        if (s.contains("microsoft") || s.contains("msn.com") || s.contains("office")
                || s.contains("azure") || s.contains("live.com") || s.contains("outlook") || s.contains("bing"))
            return MICROSOFT;
        if (s.contains("apple") || s.contains("icloud") || s.contains("mzstatic") || s.contains("itunes"))
            return APPLE;
        if (s.contains("telegram") || s.contains("t.me"))
            return TELEGRAM;
        if (s.contains("tiktok") || s.contains("tiktokcdn") || s.contains("musical.ly") || s.contains("bytedance"))
            return TIKTOK;
        if (s.contains("spotify") || s.contains("scdn.co"))
            return SPOTIFY;
        if (s.contains("zoom"))
            return ZOOM;
        if (s.contains("discord") || s.contains("discordapp"))
            return DISCORD;
        if (s.contains("github") || s.contains("githubusercontent"))
            return GITHUB;
        if (s.contains("cloudflare") || s.contains("cf-"))
            return CLOUDFLARE;

        // SNI present but not in known list → still classified as HTTPS
        return HTTPS;
    }
}