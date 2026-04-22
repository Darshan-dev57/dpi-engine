package com.dpiengine.extractor;

import com.dpiengine.parser.PacketParser;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Extracts the Server Name Indication (SNI) from TLS Client Hello packets.
 *
 * Why SNI matters for DPI
 * ========================
 * HTTPS traffic is encrypted — we can't read the page content. BUT:
 * When a browser opens an HTTPS connection, its very FIRST packet contains
 * a TLS "Client Hello" message. Inside that message, in plaintext, is the
 * domain name (e.g. "www.youtube.com"). This is called the SNI extension.
 *
 * TLS Client Hello structure:
 *   [TLS Record Header: 5 bytes]
 *     Byte 0:   Content Type = 0x16 (Handshake)
 *     Bytes 1-2: Version (0x0301 = TLS 1.0 ... 0x0303 = TLS 1.2)
 *     Bytes 3-4: Record Length
 *   [Handshake Header: 4 bytes]
 *     Byte 0:    Handshake Type = 0x01 (Client Hello)
 *     Bytes 1-3: Length (24-bit)
 *   [Client Hello Body]
 *     Bytes 0-1:   Client Version
 *     Bytes 2-33:  Random (32 bytes)
 *     Byte 34:     Session ID Length (variable)
 *     ...           Session ID
 *     2 bytes:     Cipher Suites Length
 *     ...           Cipher Suites
 *     1 byte:      Compression Methods Length
 *     ...           Compression Methods
 *     2 bytes:     Extensions Length
 *     [Extensions — we scan these for type 0x0000 = SNI]
 */
public class SniExtractor {

    // TLS constants
    private static final int CONTENT_TYPE_HANDSHAKE    = 0x16;
    private static final int HANDSHAKE_CLIENT_HELLO    = 0x01;
    private static final int EXTENSION_TYPE_SNI        = 0x0000;
    private static final int SNI_NAME_TYPE_HOST        = 0x00;

    /**
     * Attempt to extract the SNI hostname from a TCP payload that may
     * contain a TLS Client Hello.
     *
     * @param data   full packet byte array
     * @param offset byte offset where the TCP payload begins
     * @param length number of bytes in the TCP payload
     * @return the SNI hostname, or empty if not found / not a Client Hello
     */
    public static Optional<String> extract(byte[] data, int offset, int length) {
        if (length < 9) return Optional.empty();
        if (!isTlsClientHello(data, offset, length)) return Optional.empty();

        int pos = offset + 5; // skip TLS record header

        // Handshake header: type(1) + length(3)
        pos += 1; // skip handshake type (already verified above)
        pos += 3; // skip 24-bit handshake length

        // Client Hello body
        pos += 2;  // client version
        pos += 32; // random bytes

        // Session ID
        if (pos >= offset + length) return Optional.empty();
        int sessionIdLen = data[pos] & 0xFF;
        pos += 1 + sessionIdLen;

        // Cipher suites
        if (pos + 2 > offset + length) return Optional.empty();
        int cipherSuitesLen = PacketParser.readUint16BE(data, pos);
        pos += 2 + cipherSuitesLen;

        // Compression methods
        if (pos >= offset + length) return Optional.empty();
        int compressionLen = data[pos] & 0xFF;
        pos += 1 + compressionLen;

        // Extensions
        if (pos + 2 > offset + length) return Optional.empty();
        int extensionsLen = PacketParser.readUint16BE(data, pos);
        pos += 2;
        int extensionsEnd = Math.min(pos + extensionsLen, offset + length);

        // Scan extensions looking for SNI (type 0x0000)
        while (pos + 4 <= extensionsEnd) {
            int extType   = PacketParser.readUint16BE(data, pos);
            int extLength = PacketParser.readUint16BE(data, pos + 2);
            pos += 4;

            if (pos + extLength > extensionsEnd) break;

            if (extType == EXTENSION_TYPE_SNI) {
                // SNI extension format:
                //   2 bytes: SNI list length
                //   1 byte:  name type (0x00 = host_name)
                //   2 bytes: name length
                //   N bytes: hostname (ASCII)
                if (extLength < 5) break;
                // skip sni list length (2 bytes)
                int nameType   = data[pos + 2] & 0xFF;
                int nameLength = PacketParser.readUint16BE(data, pos + 3);
                if (nameType != SNI_NAME_TYPE_HOST) break;
                if (pos + 5 + nameLength > extensionsEnd) break;

                String hostname = new String(data, pos + 5, nameLength, StandardCharsets.US_ASCII);
                return Optional.of(hostname);
            }

            pos += extLength;
        }

        return Optional.empty();
    }

    /** Check if the payload starts with a TLS Handshake / Client Hello record */
    private static boolean isTlsClientHello(byte[] data, int offset, int length) {
        if (length < 9) return false;
        // Content type must be 0x16 (Handshake)
        if ((data[offset] & 0xFF) != CONTENT_TYPE_HANDSHAKE) return false;
        // TLS version: 0x0300 – 0x0304
        int version = PacketParser.readUint16BE(data, offset + 1);
        if (version < 0x0300 || version > 0x0304) return false;
        // Handshake type must be 0x01 (Client Hello)
        if ((data[offset + 5] & 0xFF) != HANDSHAKE_CLIENT_HELLO) return false;
        return true;
    }
}