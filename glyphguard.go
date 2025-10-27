/*
GlyphGuard - IDN Homograph Detector (container-ready)

Product Information:
1. Product Name: GlyphGuard
2. Author / Manufacturer: Ashkan Ebrahimi | O & TM Secure Manager Co
3. Release Date: 2025-10-27
4. Version: 1.0.0

Description:
GlyphGuard is a Go-based daemon that monitors DNS query logs, detects
IDN homograph attacks, and exports structured alerts to ELK and Syslog
(for PRTG monitoring). Supports active verification via DNS resolution or
ICMP ping fallback, with caching to minimize redundant checks.
*/

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/syslog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/norm"
)

/*
GlyphGuard - IDN Homograph Detector (container-ready)
Features:
 - watch a DNS query log file (tail)
 - extract domain + client IP
 - detect IDN / homograph against a small legit list
 - cache checks per domain+client to avoid repeated active checks
 - active verification: DNS resolve (preferred) + ping fallback
 - send structured JSON to ELK and messages to syslog
 - configurable via flags or config.yaml (simple)
*/

var (
	// Basic configurable via flags (can extend to read config.yaml)
	elkEndpoint    = flag.String("elk", "http://localhost:9200/glyphguard/_doc/", "ELK/Elasticsearch ingest endpoint (HTTP POST)")
	logPath        = flag.String("log", "/var/log/dns/queries.log", "Path to DNS queries log to watch")
	cacheMinutes   = flag.Int("cache", 30, "Cache duration in minutes for domain+client checks")
	similarityThr  = flag.Int("threshold", 90, "Similarity threshold (0-100) to flag homograph")
	noPing         = flag.Bool("no-ping", false, "Disable ICMP ping fallback (use DNS resolve only)")
	syslogNetwork  = flag.String("syslog-net", "", "Syslog network (\"\" -> local unix, or \"udp\", \"tcp\")")
	syslogAddress  = flag.String("syslog-addr", "", "Syslog address for network mode (host:port)")
	legitDomainsF  = flag.String("legit", "", "Comma-separated list of legit domains (overrides embedded list)")
	workerPoolSize = flag.Int("workers", 5, "Number of concurrent active-verification workers")
)

// default legit domains - user should extend this list for their org
var defaultLegit = []string{
	"google.com",
	"paypal.com",
	"microsoft.com",
	"securemanager.co",
	"bank.example",
}

// structures
type CacheEntry struct {
	LastChecked time.Time
}

type Alert struct {
	Timestamp      string   `json:"timestamp"`
	Domain         string   `json:"domain"`
	Punycode       string   `json:"punycode"`
	Status         string   `json:"status"`
	VerifiedAlive  bool     `json:"verified_alive"`
	CheckType      string   `json:"check_type"`
	ClientIP       string   `json:"client_ip,omitempty"`
	DestinationIPs []string `json:"destination_ips,omitempty"`
	Message        string   `json:"message,omitempty"`
}

var domainCache = struct {
	sync.RWMutex
	data map[string]CacheEntry
}{data: make(map[string]CacheEntry)}

var legitDomains []string

// helpers: normalization & similarity (simple)
func normalizeString(s string) string {
	s = strings.ToLower(s)
	s = norm.NFKC.String(s)
	var b []rune
	for _, r := range s {
		if norm.NFKC.PropertiesString(string(r)).CombiningClass() == 0 {
			b = append(b, r)
		}
	}
	return string(b)
}

func levenshteinDistance(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	dp := make([][]int, la+1)
	for i := range dp {
		dp[i] = make([]int, lb+1)
	}
	for i := 0; i <= la; i++ {
		dp[i][0] = i
	}
	for j := 0; j <= lb; j++ {
		dp[0][j] = j
	}
	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			dp[i][j] = min(dp[i-1][j]+1, min(dp[i][j-1]+1, dp[i-1][j-1]+cost))
		}
	}
	return dp[la][lb]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func similarityPercent(a, b string) int {
	dist := levenshteinDistance(a, b)
	m := max(len(a), len(b))
	if m == 0 {
		return 100
	}
	return 100 - (dist*100)/m
}

// cache key domain|client
func cacheKey(domain, client string) string {
	return domain + "|" + client
}

func shouldCheckDomain(domain, client string, cacheDur time.Duration) bool {
	k := cacheKey(domain, client)
	domainCache.RLock()
	entry, ok := domainCache.data[k]
	domainCache.RUnlock()
	if ok && time.Since(entry.LastChecked) < cacheDur {
		return false
	}
	return true
}

func markDomainChecked(domain, client string) {
	k := cacheKey(domain, client)
	domainCache.Lock()
	domainCache.data[k] = CacheEntry{LastChecked: time.Now()}
	domainCache.Unlock()
}

// resolver with timeout
func resolveDomainIPs(domain string, timeout time.Duration) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	resolver := &net.Resolver{}
	ips, err := resolver.LookupIP(ctx, "ip", domain)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out, nil
}

// ping fallback (uses system ping)
func pingDomain(domain string, timeout time.Duration) bool {
	cmd := exec.Command("ping", "-c", "1", "-W", fmt.Sprintf("%d", int(timeout.Seconds())), domain)
	var b bytes.Buffer
	cmd.Stdout = &b
	cmd.Stderr = &b
	err := cmd.Run()
	return err == nil
}

// send JSON to ELK
func sendToELK(endpoint string, alert Alert) error {
	data, _ := json.Marshal(alert)
	resp, err := http.Post(endpoint, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// detection logic: given observed domain & client, analyze + active verify
func analyzeAndAlert(observed string, clientIP string, sys *syslog.Writer, cacheDur time.Duration, similarityThr int, elk string, noPingFlag bool) {
	observed = strings.TrimSpace(observed)
	if observed == "" {
		return
	}
	observed = strings.Split(strings.Split(observed, "/")[0], ":")[0]

	unicodeDomain := observed
	if strings.HasPrefix(strings.ToLower(observed), "xn--") || strings.Contains(observed, "xn--") {
		parts := strings.Split(observed, ".")
		for i, p := range parts {
			if strings.HasPrefix(strings.ToLower(p), "xn--") {
				if dec, err := idna.ToUnicode(p); err == nil {
					parts[i] = dec
				}
			}
		}
		unicodeDomain = strings.Join(parts, ".")
	}

	skelObs := normalizeString(unicodeDomain)

	for _, legit := range legitDomains {
		skelLegit := normalizeString(legit)
		sim := similarityPercent(skelObs, skelLegit)
		if sim >= similarityThr {
			resolved, rerr := resolveDomainIPs(unicodeDomain, 2*time.Second)
			alive := false
			if rerr == nil && len(resolved) > 0 {
				alive = true
			} else if !noPingFlag {
				alive = pingDomain(unicodeDomain, 2*time.Second)
			}
			msg := fmt.Sprintf("⚠️ IDN Homograph detected: '%s' similar to '%s' (%d%%) Alive:%v client=%s resolved=%v",
				unicodeDomain, legit, sim, alive, clientIP, resolved)
			fmt.Println(msg)
			if sys != nil {
				sys.Warning(msg)
			}
			alert := Alert{
				Timestamp:      time.Now().UTC().Format(time.RFC3339),
				Domain:         unicodeDomain,
				Punycode:       observed,
				Status:         "suspected_homograph",
				VerifiedAlive:  alive,
				CheckType:      "dns_query",
				ClientIP:       clientIP,
				DestinationIPs: resolved,
				Message:        msg,
			}
			_ = sendToELK(elk, alert)
			return
		}
	}

	if unicodeDomain != observed || strings.ContainsAny(unicodeDomain, "абвгдеёжзийклмнопрстуфхцчшщъыьэюя") {
		resolved, rerr := resolveDomainIPs(unicodeDomain, 2*time.Second)
		alive := false
		if rerr == nil && len(resolved) > 0 {
			alive = true
		} else if !noPingFlag {
			alive = pingDomain(unicodeDomain, 2*time.Second)
		}
		msg := fmt.Sprintf("ℹ️ IDN observed: %s -> %s Alive:%v client=%s resolved=%v",
			observed, unicodeDomain, alive, clientIP, resolved)
		fmt.Println(msg)
		if sys != nil {
			sys.Info(msg)
		}
		alert := Alert{
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
			Domain:         unicodeDomain,
			Punycode:       observed,
			Status:         "idn_observed",
			VerifiedAlive:  alive,
			CheckType:      "dns_query",
			ClientIP:       clientIP,
			DestinationIPs: resolved,
			Message:        msg,
		}
		_ = sendToELK(elk, alert)
	}
}

var reDomain = regexp.MustCompile(`([a-zA-Z0-9\-.xn--]+(\.[a-zA-Z0-9\-.xn--]+)+)`)
var reClientIP = regexp.MustCompile(`(?:client|from|src|client=)\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})`)

func extractDomainAndClient(line string) (string, string) {
	dm := reDomain.FindString(line)
	ipm := reClientIP.FindStringSubmatch(line)
	clientIP := ""
	if len(ipm) >= 2 {
		clientIP = ipm[1]
	} else {
		ipAny := regexp.MustCompile(`([0-9]{1,3}(?:\.[0-9]{1,3}){3})`)
		am := ipAny.FindStringSubmatch(line)
		if len(am) >= 2 {
			clientIP = am[1]
		}
	}
	return dm, clientIP
}

func tailFile(path string, handler func(string)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, _ = f.Seek(0, 2)
	reader := bufio.NewReader(f)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			time.Sleep(300 * time.Millisecond)
			continue
		}
		handler(strings.TrimSpace(line))
	}
}

func main() {
	flag.Parse()
	if *legitDomainsF != "" {
		legitDomains = strings.Split(*legitDomainsF, ",")
	} else {
		legitDomains = defaultLegit
	}
	cacheDur := time.Duration(*cacheMinutes) * time.Minute

	var sys *syslog.Writer
	var err error
	if *syslogNetwork == "" {
		sys, err = syslog.New(syslog.LOG_WARNING|syslog.LOG_DAEMON, "glyphguard")
	} else {
		sys, err = syslog.Dial(*syslogNetwork, *syslogAddress, syslog.LOG_WARNING|syslog.LOG_DAEMON, "glyphguard")
	}
	if err != nil {
		log.Printf("syslog init error (continuing without syslog): %v", err)
		sys = nil
	}
	defer func() {
		if sys != nil {
			sys.Close()
		}
	}()

	jobs := make(chan [2]string, 100)
	var wg sync.WaitGroup
	for i := 0; i < *workerPoolSize; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pair := range jobs {
				domain := pair[0]
				client := pair[1]
				analyzeAndAlert(domain, client, sys, cacheDur, *similarityThr, *elkEndpoint, *noPing)
				markDomainChecked(domain, client)
			}
		}()
	}

	handler := func(line string) {
		domain, client := extractDomainAndClient(line)
		if domain == "" {
			return
		}
		if client == "" {
			client = "unknown"
		}
		if !shouldCheckDomain(domain, client, cacheDur) {
			return
		}
		select {
		case jobs <- [2]string{domain, client}:
		default:
			log.Printf("job queue full, dropping domain=%s client=%s", domain, client)
		}
	}

	log.Printf("GlyphGuard starting, watching %s", *logPath)
	err = tailFile(*logPath, handler)
	if err != nil {
		log.Fatalf("tail error: %v", err)
	}

	close(jobs)
	wg.Wait()
}
