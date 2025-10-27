#!/bin/bash
# glyphguard_test_mode.sh
# Simple test script for GlyphGuard
# Creates a temporary DNS log with one safe domain and one homograph/malicious domain

# Temp log file
LOG_FILE="./queries_test.log"

# Clear previous log
> "$LOG_FILE"

# Example client IP
CLIENT_IP="192.168.1.100"

# Safe domain
SAFE_DOMAIN="google.com"

# Malicious / homograph domain (Unicode / Punycode)
MALICIOUS_DOMAIN="xn--goog1e-8ta.com"  # example: 'gοogle.com' with Greek 'ο'

# Write test lines to log
echo "client=$CLIENT_IP query=$SAFE_DOMAIN" >> "$LOG_FILE"
echo "client=$CLIENT_IP query=$MALICIOUS_DOMAIN" >> "$LOG_FILE"

echo "Test log created at $LOG_FILE"
echo "Run GlyphGuard with:"
echo "  ./glyphguard -log $LOG_FILE -elk http://localhost:9200/glyphguard/_doc/"
