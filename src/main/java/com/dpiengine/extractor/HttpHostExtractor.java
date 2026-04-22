package com.dpiengine.extractor;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Extracts the Host header from HTTP/1.x request payloads.
 *
 * Plain HTTP (port 80) sends headers in plaintext. The "Host:" header
 * tells us exactly which website the client is visiting — perfect for DPI.
 *
 * Example HTTP request payload:
 *   GET /index.html HTTP/1.1\r\n
 *   Host: www.example.com\r\n
 *   ...
 */
public class HttpHostExtractor {

    private static final byte[][] HTTP_METHODS = {
        "GET ".getBytes(StandardCharsets.US_ASCII),
        "POST".getBytes(StandardCharsets.US_ASCII),
        "PUT ".getBytes(StandardCharsets.US_ASCII),
        "HEAD".getBytes(StandardCharsets.US_ASCII),
        "DELE".getBytes(StandardCharsets.US_ASCII),
        "PATC".getBytes(StandardCharsets.US_ASCII),
        "OPTI".getBytes(StandardCharsets.US_ASCII),
    };

    public static Optional<String> extract(byte[] data, int offset, int length) {
        if (length < 4) return Optional.empty();
        if (!isHttpRequest(data, offset)) return Optional.empty();

        // Search for "Host:" or "host:" (case-insensitive)
        for (int i = offset; i + 6 < offset + length; i++) {
            if (matchesHostHeader(data, i, offset + length)) {
                // Skip "Host:" and optional whitespace
                int start = i + 5;
                while (start < offset + length
                        && (data[start] == ' ' || data[start] == '\t')) {
                    start++;
                }
                // Find end of line (\r or \n)
                int end = start;
                while (end < offset + length
                        && data[end] != '\r' && data[end] != '\n') {
                    end++;
                }
                if (end > start) {
                    String host = new String(data, start, end - start, StandardCharsets.US_ASCII);
                    // Strip port if present (e.g. "example.com:8080" → "example.com")
                    int colon = host.indexOf(':');
                    if (colon >= 0) host = host.substring(0, colon);
                    return Optional.of(host.trim());
                }
            }
        }
        return Optional.empty();
    }

    private static boolean isHttpRequest(byte[] data, int offset) {
        for (byte[] method : HTTP_METHODS) {
            if (startsWith(data, offset, method)) return true;
        }
        return false;
    }

    /** Case-insensitive match of "Host:" at position i */
    private static boolean matchesHostHeader(byte[] data, int i, int end) {
        if (i + 5 >= end) return false;
        return (data[i]   == 'H' || data[i]   == 'h')
            && (data[i+1] == 'o' || data[i+1] == 'O')
            && (data[i+2] == 's' || data[i+2] == 'S')
            && (data[i+3] == 't' || data[i+3] == 'T')
            &&  data[i+4] == ':';
    }

    private static boolean startsWith(byte[] data, int offset, byte[] prefix) {
        if (data.length < offset + prefix.length) return false;
        for (int i = 0; i < prefix.length; i++) {
            if (data[offset + i] != prefix[i]) return false;
        }
        return true;
    }
}