# DPI Engine - Deep Packet Inspection System (Java)

This README is a full Java-only guide to the DPI engine in this repository.

It covers:

- architecture diagrams
- packet format diagrams
- runtime sequence diagrams
- class responsibility map
- end-to-end packet journey
- CLI usage, build, run, and output interpretation

## Overview

This is a Java Deep Packet Inspection (DPI) engine for offline packet analysis.
It reads `.pcap` captures, parses packets across multiple layers, extracts
application-level metadata (TLS SNI / HTTP Host), classifies traffic, applies
blocking rules, and writes a filtered output PCAP.

## Real-World Usage

- Network monitoring and traffic visibility
- Security analysis and policy validation
- Offline rule testing before production rollout
- Teaching and interview demos for TCP/IP, HTTP/HTTPS, DNS, and flow tracking

---

## Table of Contents

1. [What This Java DPI Engine Does](#1-what-this-java-dpi-engine-does)
2. [High-Level Architecture Diagram](#2-high-level-architecture-diagram)
3. [Project Structure](#3-project-structure)
4. [Data Model Diagrams](#4-data-model-diagrams)
5. [PCAP Format Diagram](#5-pcap-format-diagram)
6. [Packet Parsing Diagram](#6-packet-parsing-diagram)
7. [End-to-End Runtime Sequence](#7-end-to-end-runtime-sequence)
8. [Detailed Packet Journey](#8-detailed-packet-journey)
9. [Classification Logic Diagram](#9-classification-logic-diagram)
10. [Blocking Decision Diagram](#10-blocking-decision-diagram)
11. [Class-by-Class Deep Dive](#11-class-by-class-deep-dive)
12. [Build and Run](#12-build-and-run)
13. [CLI Reference](#13-cli-reference)
14. [Example Runs](#14-example-runs)
15. [Output Report Explained](#15-output-report-explained)
16. [Troubleshooting](#16-troubleshooting)
17. [Future Enhancements](#17-future-enhancements)

---

## 1. What This Java DPI Engine Does

The Java engine processes an offline `.pcap` file and produces a filtered `.pcap` file.

For each packet, it:

1. Reads the raw record from PCAP
2. Parses Ethernet/IP/TCP/UDP headers
3. Maps packet to a flow using five-tuple
4. Classifies app/domain via TLS SNI / HTTP Host / DNS hints
5. Applies blocking rules (IP/app/domain)
6. Forwards allowed packets to output PCAP
7. Produces final stats report

---

## 2. High-Level Architecture Diagram

```╔══════════════════════════════════════════════════════════════╗
║              HIGH-LEVEL ARCHITECTURE                         ║
╚══════════════════════════════════════════════════════════════╝

  input.pcap
      │
      ▼
┌─────────────┐
│  PcapReader │   reads global header + per-packet headers
└──────┬──────┘
       │
       ▼
┌──────────────┐
│ PacketParser │   Ethernet → IPv4 → TCP / UDP
└──────┬───────┘
       │
       ▼
┌──────────────────────┐
│       DpiEngine      │
│  ┌────────────────┐  │
│  │   Flow Table   │  │
│  └────────────────┘  │
│  ┌────────────────┐  │
│  │ Classification │  │
│  └────────────────┘  │
└────────┬─────┬───────┘
         │     │
         ▼     ▼
┌──────────┐ ┌───────────────┐
│ Blocking │ │ ReportPrinter │
│  Rules   │ │  stats + SNIs │
└────┬─────┘ └───────────────┘
     │
     ▼
┌─────────────┐
│  PcapWriter │   writes forwarded packets only
└──────┬──────┘
       │
       ▼
  output.pcap

---

## 3. Project Structure

```text
dpi-engine/
	pom.xml
	README.md
	src/main/java/com/dpiengine/
		Main.java
		model/
			AppType.java
			FiveTuple.java
			Flow.java
			RawPacket.java
			ParsedPacket.java
		parser/
			PcapReader.java
			PacketParser.java
		extractor/
			SniExtractor.java
			HttpHostExtractor.java
			DnsExtractor.java
		engine/
			DpiEngine.java
			BlockingRules.java
		util/
			PcapWriter.java
			ReportPrinter.java
```

---

## 4. Data Model Diagrams

### 4.1 Raw packet model

```text
RawPacket
	tsSec      : long
	tsUsec     : long
	inclLen    : int
	origLen    : int
	data       : byte[]
```

### 4.2 Parsed packet model

```text
ParsedPacket
	Ethernet: srcMac, dstMac, etherType
	IPv4    : hasIp, srcIp, dstIp, protocol, ttl
	L4      : hasTcp, hasUdp, srcPort, dstPort, tcpFlags, seq, ack
	Payload : payloadOffset, payloadLength
```

### 4.3 Flow model

```text
Flow
	tuple       : FiveTuple
	appType     : AppType
	sni         : String
	packetCount : long
	byteCount   : long
	blocked     : boolean
```

### 4.4 FiveTuple key

```text
FiveTuple
	srcIp    : int
	dstIp    : int
	srcPort  : int
	dstPort  : int
	protocol : int

Used as HashMap key in DpiEngine.flowTable
```

---

## 5. PCAP Format Diagram

This Java reader handles classic libpcap format.

```text
+---------------------------------------------------------+
| Global Header (24 bytes)                                |
| [magic][ver][tz][sigfigs][snaplen][network]             |
+---------------------------------------------------------+
| Packet Record #1                                         |
|   Packet Header (16 bytes): [ts_sec][ts_usec][incl][orig]|
|   Packet Data   (incl_len bytes)                         |
+---------------------------------------------------------+
| Packet Record #2                                         |
|   Packet Header (16 bytes)                               |
|   Packet Data                                             |
+---------------------------------------------------------+
| ...                                                      |
+---------------------------------------------------------+
```

Endianness is determined from the global header magic number.

---

## 6. Packet Parsing Diagram

```text
Raw bytes
	|
	+--[0..13] Ethernet Header
	|     +-- dst MAC
	|     +-- src MAC
	|     +-- EtherType (0x0800 => IPv4)
	|
	+--[14..] IPv4 Header
	|     +-- version / IHL
	|     +-- protocol (6 TCP, 17 UDP)
	|     +-- src IP / dst IP
	|
	+--[L4] TCP or UDP Header
	|     +-- src port / dst port
	|     +-- flags (TCP)
	|
	+--Payload
				+-- TLS ClientHello (SNI)
				+-- HTTP Request (Host header)
				+-- DNS query bytes
```

---

## 7. End-to-End Runtime Sequence

```text
Main
	|
	| parse args + rules
	v
DpiEngine.process(input, output)
	|
	+--> PcapReader.open(input)
	+--> PcapWriter.open(output, globalHeader)
	|
	+--> loop readNext()
					|
					+--> PacketParser.parse(raw, parsed)
					+--> flow = flowTable.computeIfAbsent(fiveTuple)
					+--> classifyFlow(flow, parsed, raw)
					+--> blocked = BlockingRules.isBlocked(...)
					+--> if blocked: dropped++
					+--> else: writer.writePacket(raw), forwarded++
	|
	+--> ReportPrinter.print(...)
	+--> done
```

---

## 8. Detailed Packet Journey

### Step 1: CLI entry

`Main` accepts:

```text
java -jar target/dpi-engine-1.0.0-jar-with-dependencies.jar <input.pcap> <output.pcap> [options]
```

Supported options:

- `--block-ip=<ipv4>`
- `--block-app=<APP>`
- `--block-domain=<substring>`
- `--help` / `-h`

### Step 2: Open files

- `PcapReader.open(...)` reads and stores input global header bytes
- `PcapWriter.open(...)` writes same global header to output

### Step 3: Read packet record

`readNext()` returns one `RawPacket` containing timestamp and raw bytes.

### Step 4: Parse protocol stack

`PacketParser.parse(raw, parsed)` populates structured fields.

Packets that are non-IPv4 or missing TCP/UDP are skipped.

### Step 5: Flow lookup

`FiveTuple` is created from parsed src/dst ip, src/dst port, and protocol.

Flow state lives in:

```java
Map<FiveTuple, Flow> flowTable
```

### Step 6: Classification

Order used by `classifyFlow(...)`:

1. TLS SNI on TCP dst port 443
2. HTTP Host on TCP dst port 80
3. DNS if src/dst port 53
4. Port fallback (443 HTTPS, 80 HTTP)

### Step 7: Block check

`BlockingRules.isBlocked(srcIp, appType, sni)` evaluates configured policy.

### Step 8: Forward/drop and counters

- blocked -> dropped count increases
- allowed -> packet written to output PCAP

### Step 9: Final report

`ReportPrinter.print(...)` prints totals and app/domain stats.

---

## 9. Classification Logic Diagram

```text
╔══════════════════════════════════════════════════════════════╗
║              CLASSIFICATION LOGIC                            ║
╚══════════════════════════════════════════════════════════════╝

              ┌─────────────────────────────┐
              │   classifyFlow(flow, pkt)   │
              └──────────────┬──────────────┘
                             │
               ┌─────────────▼─────────────┐
               │      SNI already set?     │
               └──────┬────────────┬───────┘
                  yes │            │ no
                      ▼            ▼
                  ┌────────┐  ┌──────────────────────┐
                  │ return │  │ TCP && dstPort == 443?│
                  └────────┘  └────────┬─────────┬───┘
                                  yes │         │ no
                                      ▼         ▼
                           ┌──────────────┐   ┌──────┐
                           │SniExtractor  │   │ skip │
                           │extractSni()  │   └──────┘
                           └──────┬───────┘
                                  │
                         ┌────────▼────────┐
                         │   SNI found?    │
                         └──┬──────────┬───┘
                        yes │          │ no
                            ▼          ▼
                  ┌──────────────┐  ┌──────────┐
                  │flow.sni = sni│  │ continue │
                  │app = fromSni │  └────┬─────┘
                  └──────┬───────┘       │
                         └───────┬───────┘
                                 │
               ┌─────────────────▼─────────────────┐
               │  TCP && dstPort==80 && sni empty?  │
               └────────────┬──────────────┬────────┘
                        yes │              │ no
                            ▼              ▼
                  ┌──────────────┐      ┌──────┐
                  │extractHttp   │      │ skip │
                  │  Host()      │      └──────┘
                  └──────┬───────┘
                         │
                ┌────────▼────────┐
                │  Host found?    │
                └──┬──────────┬───┘
               yes │          │ no
                   ▼          ▼
         ┌──────────────┐  ┌──────────┐
         │flow.sni = host│  │ continue │
         │app = fromSni  │  └────┬─────┘
         └──────┬────────┘       │
                └────────┬───────┘
                         │
          ┌──────────────▼──────────────┐
          │  app==UNKNOWN && port==53?  │
          └──────────┬──────────┬───────┘
                 yes │          │ no
                     ▼          ▼
               ┌─────────┐  ┌───────────────┐
               │app = DNS│  │ port fallback │
               └─────────┘  │  443 → HTTPS  │
                            │   80 → HTTP   │
                            └───────────────┘
```

---

## 10. Blocking Decision Diagram

```text
Input: srcIp, appType, sni
	 |
	 +--> Is srcIp in blockedIps? ---------- yes --> BLOCK
	 |
	 +--> Is appType in blockedApps? ------- yes --> BLOCK
	 |
	 +--> Any blockedDomain substring in sni? yes -> BLOCK
	 |
	 +--------------------------------------------- ALLOW
```

Rule matching is cumulative: if any rule matches, packet is dropped.

---

## 11. Class-by-Class Deep Dive

### Main.java

- CLI parsing and validation
- Rule construction
- Engine start
- usage/help output

### engine/DpiEngine.java

- orchestrates full pipeline
- owns `flowTable`, packet counters, app stats
- prints blocked events and final summary

### engine/BlockingRules.java

- stores block policies in memory
- supports block by IP, app, domain substring

### parser/PcapReader.java

- binary file reader for PCAP
- endian-aware uint32 parsing
- outputs `RawPacket`

### parser/PacketParser.java

- parses Ethernet, IPv4, TCP/UDP
- computes payload offset/length
- helper methods for unsigned big-endian integer reads

### extractor/SniExtractor.java

- inspects TLS ClientHello
- walks extension list
- extracts SNI hostname

### extractor/HttpHostExtractor.java

- detects HTTP methods
- scans for `Host:` header (case-insensitive)
- strips optional `:port`

### extractor/DnsExtractor.java

- helper for extracting DNS query domain from payload
- useful for future DNS reporting/rules

### util/PcapWriter.java

- writes packet record headers and packet bytes to output PCAP

### util/ReportPrinter.java

- prints final totals and app distribution chart-like lines
- prints detected domains/SNIs

### model/AppType.java

- enum of app categories
- hostname-to-app mapping via `fromSni(...)`

### model/FiveTuple.java

- flow key, `equals/hashCode`
- ip conversion utilities

### model/Flow.java

- per-flow mutable state for classification and policy decisions

### model/RawPacket.java and model/ParsedPacket.java

- raw capture representation vs parsed field representation

---

## 12. Build and Run

### Requirements

- Java 17+
- Maven 3.8+

### Build

```bash
mvn clean package
```

Artifacts:

- `target/dpi-engine-1.0.0.jar`
- `target/dpi-engine-1.0.0-jar-with-dependencies.jar`

### Run

```bash
java -jar target/dpi-engine-1.0.0-jar-with-dependencies.jar input.pcap output.pcap
```

---

## 13. CLI Reference

```text
Usage:
	java -jar target/dpi-engine-1.0.0-jar-with-dependencies.jar <input.pcap> <output.pcap> [options]

Options:
	--block-ip=<ipv4>         Block traffic by source IP
	--block-app=<appType>     Block traffic by app (e.g. YOUTUBE, NETFLIX)
	--block-domain=<domain>   Block traffic by domain/SNI substring
	--help, -h                Show help
```

---

## 14. Example Runs

### Basic

```bash
java -jar target/dpi-engine-1.0.0-jar-with-dependencies.jar test_dpi.pcap output.pcap
```

### Block one app

```bash
java -jar target/dpi-engine-1.0.0-jar-with-dependencies.jar test_dpi.pcap output.pcap --block-app=YOUTUBE
```

### Block app + domain + source IP

```bash
java -jar target/dpi-engine-1.0.0-jar-with-dependencies.jar test_dpi.pcap output.pcap --block-app=NETFLIX --block-domain=facebook --block-ip=192.168.1.50
```

### Quick local workspace test

```bash
java -jar target/dpi-engine-1.0.0-jar-with-dependencies.jar ../Packet_analyzer/test_dpi.pcap sample_output.pcap
```

---

## 15. Output Report Explained

Typical runtime output sections:

1. Banner
2. Input path
3. Optional `[BLOCKED]` lines
4. Final report table
5. Output file path

### Metric meanings

- Total Packets: packets processed in loop
- Forwarded: packets written to output PCAP
- Dropped: packets denied by rules
- Active Flows: unique five-tuples
- Application Breakdown: packet counts by `AppType`

### Report diagram

```text
+----------------------------------------------------------+
| PROCESSING REPORT                                        |
+----------------------------------------------------------+
| Total Packets  | N                                       |
| Forwarded      | M                                       |
| Dropped        | K                                       |
| Active Flows   | F                                       |
+----------------------------------------------------------+
| APPLICATION BREAKDOWN                                    |
| HTTPS      #######                                       |
| DNS        ##                                            |
| YOUTUBE    #                                             |
| ...                                                      |
+----------------------------------------------------------+
| Detected Domains/SNIs                                    |
|  - www.youtube.com -> Youtube                            |
|  - github.com      -> Github                             |
+----------------------------------------------------------+
```

---

## 16. Troubleshooting

### `Failed to process pcap: ...`

- verify input file exists
- verify input is valid `.pcap`
- verify output directory is writable

### No domain detection (mostly HTTPS/HTTP labels)

- capture may miss ClientHello packets
- payload may be truncated
- traffic might be encrypted after initial handshake only

### `--block-app` not matching

- use enum names like `YOUTUBE`, `DISCORD`, `NETFLIX`

### Empty output file

- all packets may be blocked by rules
- or parsing skipped non-IPv4/non-TCP/UDP packets

---

## 17. Future Enhancements

Possible Java-only roadmap:

1. Multi-thread worker pipeline in Java
2. DNS domain extraction integration into main classifier
3. Rule file loading (`--rules=<path>`)
4. Optional destination port blocking
5. QUIC/HTTP3 heuristics
6. JUnit tests for parser and extractors
7. Per-flow export (JSON/CSV report)
8. Kubernetes deployment for orchestration demos
9. Real-time capture mode (instead of offline-only PCAP input)
10. Dashboard for live/near-live analytics

---

## Tech Stack

- Java 17
- Maven
- PCAP binary parsing (custom parser/writer)
- Networking protocols: Ethernet, IPv4, TCP/UDP, DNS, HTTP, TLS SNI

---

## Key Learnings

- Byte-level packet parsing and protocol decoding
- End-to-end packet flow from link layer to application metadata
- Stateful flow tracking using five-tuple keys
- HTTPS classification via TLS ClientHello SNI
- Rule-based filtering by IP, application, and domain substring

---

## Final Summary

This Java DPI engine already provides a complete offline inspection pipeline:

- binary PCAP read/write
- byte-level protocol parsing
- flow-state tracking
- SNI/Host-based app detection
- configurable blocking
- clear reporting output

It is designed to be understandable first, while still being practical for real packet analysis and policy filtering tasks.
