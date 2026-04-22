package com.dpiengine.extractor;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Extracts the queried domain name from a DNS request.
 *
 * DNS packet structure (header = 12 bytes):
 *   Bytes 0-1:  Transaction ID
 *   Bytes 2-3:  Flags  (bit 15 = QR: 0=query, 1=response)
 *   Bytes 4-5:  QDCOUNT (number of questions)
 *   Bytes 6-7:  ANCOUNT
 *   Bytes 8-9:  NSCOUNT
 *   Bytes 10-11: ARCOUNT
 *   [Question section starts at byte 12]
 *
 * Domain name encoding (label format):
 *   Each label is prefixed by its length byte.
 *   The sequence ends with a 0-length byte.
 *   Example: "www.google.com" → [3]www[6]google[3]com[0]
 */
public class DnsExtractor {

    public static Optional<String> extractQuery(byte[] data, int offset, int length) {
        if (length < 12) return Optional.empty();

        // QR bit (bit 7 of byte 2): 0 = query, 1 = response
        if ((data[offset + 2] & 0x80) != 0) return Optional.empty();

        // QDCOUNT must be > 0
        int qdcount = ((data[offset + 4] & 0xFF) << 8) | (data[offset + 5] & 0xFF);
        if (qdcount == 0) return Optional.empty();

        // Parse first question's QNAME starting at offset + 12
        int pos = offset + 12;
        StringBuilder domain = new StringBuilder();

        while (pos < offset + length) {
            int labelLen = data[pos] & 0xFF;
            if (labelLen == 0) break;             // end of domain
            if (labelLen > 63) break;             // compression pointer — skip for now
            pos++;
            if (pos + labelLen > offset + length) break;
            if (domain.length() > 0) domain.append('.');
            domain.append(new String(data, pos, labelLen, StandardCharsets.US_ASCII));
            pos += labelLen;
        }

        return domain.length() == 0 ? Optional.empty() : Optional.of(domain.toString());
    }
}