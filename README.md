# 🛡️ GlyphGuard

**GlyphGuard** is an **IDN Homograph Detector** designed to monitor DNS query logs, detect suspicious domains, and send alerts to **ELK Stack** and **Syslog/PRTG**.  
Protect your network from phishing and homograph attacks with real-time detection and active verification.

---

## ⚡ Features

- **IDN Homograph Detection**: Detect visually similar/malicious domains using Unicode normalization and similarity scoring.
- **Active Verification**: Optionally perform DNS resolve or ICMP ping for suspicious domains.
- **Caching**: Avoid repeated checks on same domain+client combination to reduce bandwidth.
- **Integration Ready**: Send alerts to ELK (JSON) and Syslog (PRTG dashboards).
- **Containerized**: Runs in Docker for easy deployment anywhere.
- **Configurable**: CLI flags or `config.yaml` for flexible setup.

---

## 🏗️ Architecture Overview

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
```
## 🚀 Installation & Running

### 1. Prerequisites

- Go 1.21+  
- Docker (optional)  
- Access to DNS query logs  
- ELK Stack or Syslog server (optional)

---

### 2. Clone Repository

```bash
git clone https://github.com/securemanager/GlyphGuard.git
cd GlyphGuard
```
# ── GlyphGuard: Run & Configuration ──

## 1) Run Locally

After building the binary:

```bash
# Run GlyphGuard on a log file
./glyphguard -log ./queries.log -elk http://localhost:9200/glyphguard/_doc/
```
## 2) Create test log and run detection
bash glyphguard_test_mode.sh
./glyphguard -log ./queries_test.log -elk http://localhost:9200/glyphguard/_doc/

## 3) Example config.yaml
```text
log_path: /var/log/dns/queries.log
elk_endpoint: http://localhost:9200/glyphguard/_doc/
cache_minutes: 30
similarity_threshold: 90
worker_pool_size: 5
syslog:
  network: udp
  address: 127.0.0.1:514
legit_domains:
  - google.com
  - paypal.com
  - securemanager.co
```
## 4) Run in Docker (Optional)
```bash
# Build Docker image
docker build -t glyphguard .

# Run container with log volume mounted
docker run -d --name glyphguard \
  -v "$(pwd)/queries.log":/var/log/dns/queries.log:ro \
  glyphguard
```


