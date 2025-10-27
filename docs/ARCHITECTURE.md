# GlyphGuard Architecture

**GlyphGuard** is an IDN Homograph Detector for monitoring DNS query logs, detecting suspicious domains, and exporting alerts to ELK and Syslog (PRTG ready). This document explains the overall architecture and data flow.

---

## 1. Components

### 1.1 GlyphGuard Daemon
- **Language:** Go
- **Function:** 
  - Watches DNS query log files (tail mode)
  - Extracts domains and client IPs
  - Normalizes and checks similarity against a whitelist
  - Performs active verification (DNS resolve / ICMP ping)
  - Caches recent checks to reduce repeated verification
  - Sends alerts to ELK and Syslog

### 1.2 Configurations
- **Flags / config.yaml**
  - Log file path
  - ELK endpoint
  - Cache duration
  - Similarity threshold
  - Worker pool size
  - Syslog network/address
  - Legitimate domains list

### 1.3 ELK Stack
- **Function:** Receives structured JSON alerts
- **Purpose:** Centralized storage, search, and visualization of alerts
- **Integration:** HTTP POST from GlyphGuard daemon

### 1.4 Syslog / PRTG
- **Function:** Sends textual alerts for monitoring tools
- **Purpose:** Quick alert notifications, integration with PRTG for dashboards

### 1.5 Optional Docker Container
- **Purpose:** Containerize GlyphGuard for deployment on any host
- **Includes:** Go binary, configuration file, logs directory
- **EntryPoint:** glyphguard executable

---

## 2. Data Flow

```text
+------------------+
| DNS Query Log     |
+------------------+
          |
          v
+------------------+
| GlyphGuard Daemon|
+------------------+
          |
          v
  Normalize + similarity check
          |
          v
  Active Verification
  (DNS resolve / ping fallback)
          |
          v
+-------------------+
| Cache recent checks|
+-------------------+
          |
          +----> [ELK Stack] (JSON alert)
          |
          +----> [Syslog / PRTG] (text alert)
