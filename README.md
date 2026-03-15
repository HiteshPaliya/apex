# Apex

> **Automated bug bounty reconnaissance and exploitation orchestrator for Kali Linux / WSL2**

Apex is a production-grade, decision-tree driven scanning engine that takes a target domain from zero to a full vulnerability report — automatically. It fingerprints each discovered host, selects the right tools for the detected tech stack, runs them in parallel, deduplicates findings, and fires real-time Discord/Slack alerts the moment something critical lands.

---

## Table of Contents

- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [All Options](#all-options)
- [Scan Phases](#scan-phases)
- [Tools Integrated](#tools-integrated)
- [Decision Tree Logic](#decision-tree-logic)
- [Output Files](#output-files)
- [OOB / Blind Vulnerability Detection](#oob--blind-vulnerability-detection)
- [Authenticated Scans](#authenticated-scans)
- [Confidence Scoring](#confidence-scoring)
- [WAF Detection & Evasion](#waf-detection--evasion)
- [Checkpoint & Resume](#checkpoint--resume)
- [Notifications](#notifications)
- [Troubleshooting](#troubleshooting)
- [Disclaimer](#disclaimer)

---

## How It Works

```
Target domain
     │
     ▼
Phase 1 ── Recon ──────────── subfinder + amass + crt.sh → 100s of subdomains
     │                        dnsx CNAME resolution → takeover detection
     │                        dig AXFR → zone transfer attempts
     ▼
Phase 2 ── Fingerprint ─────── httpx probes all live hosts → tech stack profiles
     │                        wafw00f per host → WAF detected? rate drops 80%
     ▼
Phase 3 ── Discovery ───────── per host, in parallel:
     │                        naabu port scan · gau historical URLs
     │                        katana JS crawl · feroxbuster dir brute-force
     │                        byp4xx 403 bypass · git-dumper repo dump
     │                        SecretJSRunner hardcoded secrets · arjun params
     │                        S3/GCS/Azure bucket enumeration
     ▼
Phase 4 ── Vuln Scan ───────── nuclei with host-specific tag sets
     │                        (WordPress → wp tags, Spring → actuator tags, etc.)
     ▼
Phase 5 ── Injection ───────── gf categorises param URLs by injection type
     │                        sqlmap (SQLi) · dalfox (XSS) · SSRFRunner (SSRF)
     │                        crlfuzz (CRLF) · Corsy (CORS) · JWTRunner
     ▼
Phase 6 ── Specialised ─────── smuggler (HTTP smuggling) · nikto · WPScan
     │                        JWT algorithm attacks · cloud bucket write tests
     ▼
     └── Report ─────────────  REPORT.md + REPORT.json
                               Real-time Discord/Slack on critical/high findings
```

Every finding is SHA-256 deduplicated across all tools. The same vulnerability found by nuclei and feroxbuster produces exactly one report entry.

---

## Architecture

```
apex.py  =  cat core.py attack.py
              │                │
        core.py          attack.py
        ───────          ─────────
        Constants        NucleiRunner
        Logging          GFFilterRunner
        ToolRegistry     SqlmapRunner
        OOBManager       DalfoxRunner
        Finding +        SSRFRunner
        FindingStore     CrlfuzzRunner
        Checkpoint       CorsyRunner
        BaseRunner       JWTRunner
                         SmugglerRunner
        SubfinderRunner  NiktoRunner
        DNSXRunner       WpscanRunner
        HttpxFP          S3ScannerRunner
        WafRunner        DecisionTree
        VHostRunner      Reporter
        NaabuRunner      Orchestrator
        FeroxbusterRunner  main()
        Byp4xxRunner
        GauRunner
        KatanaRunner
        ParamDiscoveryRunner
        GitDumperRunner
        SecretJSRunner
```

`core.py` and `attack.py` are standalone — `apex.py` is always produced by:

```bash
cat core.py attack.py > apex.py
```

Edit either file independently, then rebuild.

---

## Requirements

- **OS:** Kali Linux 2023+ or Ubuntu 22.04+ (WSL2 supported)
- **Python:** 3.10+
- **Go:** 1.22+ (for ProjectDiscovery tools)
- **Ruby:** 2.7+ (for WPScan)
- **RAM:** 4GB minimum, 8GB recommended for large targets
- **Disk:** 5GB for SecLists + tool binaries

---

## Installation

```bash
# Clone the repo
git clone https://github.com/yourhandle/apex.git
cd apex

# Run the installer — sets up all 33 tools automatically
chmod +x install.sh && ./install.sh

# Reload PATH
source ~/.bashrc

# Verify everything is found
python3 apex.py --tools-check
```

The installer handles: Go environment, all ProjectDiscovery tools, Python tools (sqlmap, arjun, wafw00f, git-dumper, trufflehog), Ruby tools (WPScan), SecLists wordlists, gf patterns, and writes `~/.bugbounty_tools.json` with all resolved tool paths.

---

## Configuration

### API Keys — `~/.bugbounty_config.yaml`

More API keys means more subdomain sources for subfinder and better passive recon coverage.

```yaml
api_keys:
  shodan:         "YOUR_SHODAN_KEY"
  virustotal:     "YOUR_VT_KEY"
  securitytrails: "YOUR_ST_KEY"
  censys_id:      "YOUR_CENSYS_ID"
  censys_secret:  "YOUR_CENSYS_SECRET"

# Fires on every critical + high finding automatically
webhook_url: "https://discord.com/api/webhooks/..."
```

### subfinder Provider Config — `~/.config/subfinder/provider-config.yaml`

```yaml
virustotal:
  - YOUR_VT_KEY
shodan:
  - YOUR_SHODAN_KEY
securitytrails:
  - YOUR_ST_KEY
```

### OOB Server — `~/.config/interactsh-client/config.yaml`

For blind SSRF/XXE/RCE detection. Public server requires no setup; a self-hosted VPS eliminates DNS resolver noise and gives you complete privacy.

```yaml
# Public server (default, no setup needed)
server: oast.fun
token: ""
json: true
verbose: true
```

```yaml
# Self-hosted VPS (recommended)
server: http://YOUR_VPS_IP.nip.io
token: ""
json: true
verbose: true
```

**Setting up a self-hosted interactsh server:**

```bash
# On your VPS — install and run
go install github.com/projectdiscovery/interactsh/cmd/interactsh-server@latest

sudo interactsh-server \
  -domain YOUR_VPS_IP.nip.io \
  -ip     YOUR_VPS_IP \
  -listen-ip 0.0.0.0

# Required open ports: 53 TCP/UDP · 80 · 443
```

### WPScan API Token

```bash
export WPSCAN_API_TOKEN="your_token"
# Add to ~/.bashrc for persistence
```

---

## Usage

### Quickstart

```bash
python3 apex.py -t example.com
```

### Recommended — full scan

```bash
python3 apex.py -t example.com \
  --oob \
  --scope scope.txt \
  --output ./results \
  --rate-limit 50 \
  --workers 3 \
  --webhook "https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN"
```

### Authenticated scan — cookie

```bash
# F12 → Network → any request → copy the Cookie: header value
python3 apex.py -t example.com \
  --oob \
  --cookie "session=abc123; auth_token=xyz; _ga=GA1.2.xxx"
```

### Authenticated scan — Bearer / JWT

```bash
# F12 → Network → any /api/ request → copy Authorization: Bearer ...
python3 apex.py -t example.com \
  --oob \
  --bearer "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0..."
```

### Authenticated scan — both + extra headers

```bash
python3 apex.py -t example.com \
  --oob \
  --cookie "session=abc123" \
  --bearer "eyJhbGciOiJSUzI1NiJ9..." \
  --header "X-Tenant-ID: corp" \
  --header "X-API-Version: 2"
```

### Scoped scan (bug bounty programmes)

```bash
cat > scope.txt << 'EOF'
*.example.com
example.com
*.api.example.com
# lines starting with # are ignored
EOF

python3 apex.py -t example.com --oob --scope scope.txt
```

### Single phase

```bash
python3 apex.py -t example.com --phase inject     # injection testing only
python3 apex.py -t example.com --phase recon      # subdomain recon only
python3 apex.py -t example.com --phase special    # JWT/smuggling/WPScan only
```

### Resume after interruption

```bash
# Ctrl+C saves checkpoint automatically — resume from exactly where it stopped
python3 apex.py -t example.com --oob --resume
```

### High-value target — slow and careful

```bash
python3 apex.py -t example.com \
  --oob \
  --scope scope.txt \
  --rate-limit 20 \
  --workers 1 \
  --min-confidence firm \
  --webhook "https://discord.com/api/webhooks/..."
```

### Verify tool installation

```bash
python3 apex.py --tools-check
```

---

## All Options

| Flag | Default | Description |
|---|---|---|
| `-t, --target` | **required** | Target domain (e.g. `example.com`) |
| `--oob` | off | Start interactsh for blind OOB detection |
| `--scope` | none | Path to `scope.txt` — wildcard patterns supported |
| `--output` | `./bounty_output` | Output root directory |
| `--rate-limit N` | `100` | Max requests/sec per tool |
| `--workers N` | `3` | Parallel host scanning threads |
| `--cookie` | none | Full cookie string for authenticated scans |
| `--bearer` | none | JWT / Bearer token |
| `--header` | none | Extra header, repeatable: `'X-Foo: bar'` |
| `--webhook` | none | Discord or Slack webhook URL |
| `--min-confidence` | `tentative` | Minimum confidence: `certain`, `firm`, `tentative` |
| `--phase` | `all` | One of: `recon` `discover` `vuln` `inject` `special` `all` |
| `--resume` | off | Resume from checkpoint, skip completed steps |
| `--tools-check` | off | Print tool availability and exit |

---

## Scan Phases

### Phase 1 — Recon
*Runs once on the root domain*

| Tool | What it does |
|---|---|
| subfinder + amass | Passive subdomain enumeration across 50+ sources |
| crt.sh | Certificate transparency log mining |
| dig AXFR | DNS zone transfer attempt on every nameserver |
| dnsx | CNAME resolution + subdomain takeover fingerprinting |

### Phase 2 — Fingerprinting
*Runs once across all discovered subdomains*

| Tool | What it does |
|---|---|
| httpx | Live host detection, status codes, page title, tech stack |
| wafw00f | WAF detection per host — triggers automatic rate reduction + evasion |

### Phase 3 — Discovery
*Runs per live host, in parallel*

| Tool | What it does |
|---|---|
| naabu | Port scan across 30 dangerous ports (Docker, Redis, Elasticsearch, etcd, Kubelet...) |
| gau + waybackurls | Historical URL collection from Wayback Machine, CommonCrawl, OTX |
| katana | Active JS-aware crawl with link extraction |
| feroxbuster / ffuf | Recursive directory and file brute-force with 200+ extensions |
| byp4xx | 403 bypass via header tricks and path normalisation variants |
| gobuster vhost | Virtual host discovery (skipped on CDN targets automatically) |
| git-dumper + trufflehog | `.git` exposure detection → full repo dump → secret scanning |
| SecretJSRunner | Hardcoded API keys, source maps, `NEXT_PUBLIC_` secrets in JS bundles |
| arjun + paramspider | Hidden parameter discovery on all crawled endpoints |
| S3ScannerRunner | AWS S3, GCS, Azure Blob public bucket enumeration (13 name variants) |

### Phase 4 — Vulnerability Scanning
*Runs per host with tailored nuclei tag sets*

Nuclei runs 9000+ templates. Tags are selected per host based on fingerprinted stack:

| Detected Tech | Additional Nuclei Tags |
|---|---|
| WordPress | `wordpress` |
| Laravel / PHP | `laravel`, `php` |
| Spring / Tomcat / Struts | `java`, `spring`, `actuator`, `apache` |
| Node.js / Next.js / Nuxt | `node`, `nodejs` |
| Django / Flask / FastAPI | `python` |
| AWS / S3 / CloudFront | `aws`, `s3`, `cloud` |
| Firebase / GCP | `gcp`, `firebase`, `cloud` |
| Azure | `azure`, `cloud` |
| Elasticsearch / Kibana | `elasticsearch` |
| Redis | `redis` |
| MongoDB | `mongodb` |
| GraphQL | `graphql`, `api` |
| *Always* | `misconfig` `exposure` `cve` `sqli` `xss` `ssrf` `ssti` `xxe` `lfi` `rce` `idor` `jwt` `oauth` `saml` |

### Phase 5 — Injection Testing
*Runs per host, in parallel*

| Runner | Tool | What it tests |
|---|---|---|
| GFFilterRunner | gf | Categorises all collected URLs by injection type (sqli/xss/ssrf/lfi/ssti/idor/rce) |
| SqlmapRunner | sqlmap | SQL injection — time-based blind, boolean blind, error-based, union query |
| DalfoxRunner | dalfox | Reflected XSS, DOM XSS, blind XSS (OOB callback) |
| SSRFRunner | SSRFmap | SSRF via URL parameters, IMDS endpoint detection, OOB confirmation |
| CrlfuzzRunner | crlfuzz | CRLF injection / HTTP response splitting |
| CorsyRunner | Corsy | CORS misconfiguration — null origin, subdomain, credentialed |
| JWTRunner | jwt_tool | none algorithm, algorithm confusion, kid path traversal, kid SQLi, jku injection, expired token acceptance |

### Phase 6 — Specialised Attacks
*Runs per host, in parallel*

| Runner | Tool | What it tests |
|---|---|---|
| SmugglerRunner | smuggler.py | HTTP request smuggling — CL.TE, TE.CL, CL.0, HTTP/2 downgrade |
| NiktoRunner | nikto | General web server misconfigs (skipped automatically on CDN targets) |
| WpscanRunner | wpscan | WordPress user enumeration, plugin CVEs, theme CVEs, config exposure |
| S3ScannerRunner | built-in | Public cloud storage write access |

---

## Tools Integrated

### Go — ProjectDiscovery Suite
`subfinder` `httpx` `naabu` `nuclei` `katana` `dnsx` `interactsh-client` `dalfox` `gau` `waybackurls` `gf` `anew` `qsreplace` `crlfuzz` `ffuf` `gobuster`

### System Packages
`nmap` `nikto` `sqlmap` `masscan`

### Python
`arjun` `paramspider` `wafw00f` `git-dumper` `trufflehog`

### Python — Cloned Tools
`jwt_tool` `SSRFmap` `Corsy` `LinkFinder` `SecretFinder` `smuggler`

### Ruby
`wpscan`

### Wordlists
SecLists — installed to `/usr/share/seclists`

---

## Decision Tree Logic

`DecisionTree` runs per host after fingerprinting. It doesn't run everything on every host — it makes real conditional decisions:

| Condition | Decision |
|---|---|
| CDN detected | Skip `VHostRunner` (Host header meaningless), skip `NiktoRunner` |
| WAF detected | Rate limit → 20% of base, evasion headers rotate on all tool invocations |
| Reverse proxy detected (nginx/traefik/haproxy/etc.) | Enable `SmugglerRunner` + add `http-request-smuggling` nuclei tag |
| WordPress fingerprinted | Enable `WpscanRunner` + add `wordpress` nuclei tags |
| JWT found in any response | Enable full `JWTRunner` attack suite |
| No WordPress detected | `WpscanRunner` skipped entirely |

The full decision log for every host is included in `REPORT.md` — you can see exactly why each runner was included or skipped.

---

## Output Files

```
bounty_output/
└── example_com/
    ├── REPORT.md                    ← Human-readable findings, sorted by severity
    ├── REPORT.json                  ← Machine-readable full output
    ├── checkpoint.json              ← Resume state
    ├── oob_callbacks.json           ← Raw interactsh callback log
    ├── subfinder/example.com/
    │   ├── subfinder.txt
    │   ├── amass.txt
    │   └── all_subdomains.txt       ← Merged, sorted unique subdomains
    ├── httpx_fp/example.com/
    │   └── httpx_results.json       ← Tech profiles for all live hosts
    ├── nuclei/sub.example.com/
    │   └── nuclei_results.json
    ├── feroxbuster/sub.example.com/
    │   ├── hits_200.txt
    │   ├── hits_403.txt             ← Fed into byp4xx
    │   └── stderr.log              ← Tool stderr (useful for debugging)
    ├── gf_filter/sub.example.com/
    │   ├── sqli_urls.txt            ← Fed into sqlmap
    │   ├── xss_urls.txt             ← Fed into dalfox
    │   ├── ssrf_urls.txt            ← Fed into SSRFRunner
    │   └── ...
    └── ...                          ← One directory per runner per host
```

**`REPORT.json` schema:**

```json
{
  "target":    "example.com",
  "timestamp": "2024-01-15T22:30:00Z",
  "summary":   {"critical": 2, "high": 5, "medium": 8, "low": 3, "info": 41},
  "total":     59,
  "live_hosts": ["https://example.com", "https://api.example.com"],
  "oob_callbacks": [...],
  "decision_log": {
    "api.example.com": {
      "runners": [["nuclei", "Always: CVE scanning"], ...],
      "skipped": {"wpscan": "WordPress not detected"}
    }
  },
  "findings": [
    {
      "checklist_id": "ss2",
      "title":        "SSRF→IMDS via param 'url'",
      "severity":     "critical",
      "confidence":   "certain",
      "detail":       "Cloud metadata returned via ?url=",
      "evidence":     "ami-id: ami-0abcdef...",
      "tool":         "ssrf",
      "target":       "api.example.com",
      "remediation":  "Validate and whitelist outbound URL destinations",
      "timestamp":    "2024-01-15T22:45:12Z"
    }
  ]
}
```

---

## OOB / Blind Vulnerability Detection

Out-of-band detection catches vulnerabilities that don't reflect in HTTP responses — blind SSRF, blind XSS, XXE, Log4Shell, command injection with no output.

Every probe gets a **unique subdomain label** so callbacks are correlated back to the exact test that triggered it:

```
http://ssrfprobe.YOUR_DOMAIN  →  SSRF parameter test
http://dalfoxblind.YOUR_DOMAIN  →  Blind XSS test
http://ssrfmap.YOUR_DOMAIN    →  SSRFmap probe
```

When a real callback fires, you see:

```
[OK] OOB! HTTP from 203.0.113.42 uid=ssrfprobe ctx=SSRF on api.example.com
```

**Using the public server (no setup needed):**

```bash
python3 apex.py -t example.com --oob
```

**Using your own VPS (recommended — no Cloudflare DNS noise, full privacy):**

```bash
# 1. Configure the client
mkdir -p ~/.config/interactsh-client
cat > ~/.config/interactsh-client/config.yaml << 'EOF'
server: http://YOUR_VPS_IP.nip.io
token: ""
json: true
verbose: true
EOF

# 2. Test end-to-end
interactsh-client &
sleep 3 && curl http://PRINTED_PROBE_DOMAIN/test
# Should immediately show DNS + HTTP interactions

# 3. Run scan with OOB
python3 apex.py -t example.com --oob
```

---

## Authenticated Scans

Authentication unlocks the real attack surface — IDOR against user-owned resources, post-login API endpoints, JWT analysis against your actual token, and crawler access to gated content.

### Getting session credentials

**Cookie-based (most web apps):**
1. Open target in Chrome → Log in
2. F12 → Network → click any request → Headers tab
3. Copy the full `Cookie:` header value

**JWT / Bearer (mobile apps, SPAs, REST APIs):**
1. Open target in Chrome → Log in
2. F12 → Network → click any `/api/` request → Headers tab
3. Copy `Authorization: Bearer eyJ...`

### Running authenticated scans

```bash
# Cookie only
python3 apex.py -t example.com --cookie "session=abc; auth=xyz"

# Bearer token only
python3 apex.py -t example.com --bearer "eyJhbGciOiJSUzI1NiJ9..."

# Both (common for modern SPAs)
python3 apex.py -t example.com \
  --cookie "session=abc" \
  --bearer "eyJhbGciOiJSUzI1NiJ9..."

# With custom headers (multi-tenant apps, API versioning)
python3 apex.py -t example.com \
  --cookie "session=abc" \
  --header "X-Tenant-ID: corp" \
  --header "X-API-Version: 2"
```

### Two-account IDOR testing

Create two accounts (Account A and Account B). Run the scan authenticated as Account A. Note Account B's user ID, order ID, or resource IDs from their public profile. The scanner will attempt to access B's resources while authenticated as A — a 200 response confirms IDOR.

---

## Confidence Scoring

Every finding is assigned a confidence level:

| Level | Meaning | Examples |
|---|---|---|
| `certain` | Directly confirmed, zero false positives | OOB callback received · AXFR zone data returned · sqlmap confirmed injection · `.git/HEAD` returned `ref: refs/` · takeover fingerprint in HTTP body |
| `firm` | Strong evidence, very unlikely false positive | Nuclei template match with extracted evidence · dalfox XSS with working PoC payload · open dangerous port with banner |
| `tentative` | Pattern match — manual verification needed | gf URL pattern matches · subdomain enumeration · historical URL patterns · JS endpoint extraction · 403 hits |

**Filter output by confidence level:**

```bash
# Confirmed findings only — zero noise, safe for reports
python3 apex.py -t example.com --min-confidence certain

# Confirmed + strong evidence — recommended for triage
python3 apex.py -t example.com --min-confidence firm

# Everything including pattern matches (default)
python3 apex.py -t example.com --min-confidence tentative
```

---

## WAF Detection & Evasion

Apex automatically runs `wafw00f` at the start of each host's discovery phase. When a WAF is detected:

1. **Rate limit drops to 20%** of your `--rate-limit` value automatically — no manual intervention needed
2. **Evasion headers rotate** on every request:
   - `X-Forwarded-For: <random IP>`
   - `X-Real-IP: <different random IP>`
3. **All CLI tools** (feroxbuster, sqlmap, dalfox, nuclei) receive the same rotating evasion headers via their respective header flags
4. **VHost and Nikto** are skipped on CDN targets where results would be unreliable

The detected WAF name is logged in real time and included in the markdown report.

---

## Checkpoint & Resume

Every completed `(runner, host)` pair is written to `checkpoint.json` immediately after finishing. If the scan is interrupted for any reason:

```bash
# Original run — interrupted by Ctrl+C, crash, or timeout
python3 apex.py -t example.com --oob --output ./results

# Resume — skips all completed steps, picks up exactly where it stopped
python3 apex.py -t example.com --oob --output ./results --resume
```

Without `--resume`, a fresh run wipes the checkpoint and starts clean.

The checkpoint also accumulates shared cross-phase data — discovered param URLs, 403 hits, and JS URLs are available to later phases even after a resume.

---

## Notifications

Apex sends real-time webhook alerts for every **critical** and **high** severity finding.

```bash
# Discord
python3 apex.py -t example.com \
  --webhook "https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN"

# Slack
python3 apex.py -t example.com \
  --webhook "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
```

Each alert includes: severity label, target host, finding title, checklist ID, tool name, and evidence (up to 1024 characters).

---

## Troubleshooting

**sqlmap runs for hours without finishing**

Cloudflare and similar WAFs throttle every sqlmap payload to near-zero rate. Verify your `attack.py` has these three flags in `SqlmapRunner`:

```python
"--crawl",    "0",      # don't follow links, test only the given URL
"--smart",              # skip parameters with no injection signals
"--time-sec", "10",     # abort a time-based payload after 10 seconds
```

**Hundreds of OOB DNS callbacks from `172.68.x.x` every 5 seconds**

These are Cloudflare DNS resolver heartbeats — `interactsh-client` polling `oast.fun` through Cloudflare's infrastructure. Not real callbacks. Two fixes:

1. Switch to a self-hosted VPS interactsh server (eliminates the issue entirely)
2. Apply `patch_oob_noise.py` to filter known resolver IP ranges from callback processing

**`httpx_fp` fingerprints 0 live hosts**

httpx wrote an empty or malformed JSON file. Check:

```bash
cat bounty_output/target_com/httpx_fp/target.com/httpx_results.json | head -3
cat bounty_output/target_com/httpx_fp/target.com/stderr.log
```

**`interactsh-client` fails to register**

```bash
# Verify your VPS server is running
ps aux | grep interactsh-server

# Verify ports are open
curl http://YOUR_VPS_IP.nip.io/
sudo tcpdump -i any -n port 53   # watch for DNS traffic
```

**`secretfinder` shows ✗ in --tools-check**

secretfinder is installed as a pip package (accessible via `secretfinder` command) but ToolRegistry looks for it as a file path. Fix in `core.py`:

Change `("secretfinder", "path")` → `("secretfinder", "which")` in `TOOL_DEFS` and remove `"secretfinder": SECRETFINDER` from `_PATH_TOOLS`.

**amass prompts for sudo password**

Amass on some Kali versions requires elevated privileges for raw socket access. Either prefix with `sudo`, or remove amass from `SubfinderRunner` if you don't want the prompt — subfinder alone provides good coverage.

**Scan stuck with no visible progress**

Check per-tool stderr logs — they capture all tool error output:

```bash
find bounty_output/ -name "stderr.log" -newer /tmp/scan_start | xargs grep -l "error\|Error\|failed"
```

---

## Disclaimer

Apex is intended for use by security professionals and authorised bug bounty hunters operating within the scope of a legitimate security programme.

**Only scan targets you have explicit written permission to test.**

Unauthorised scanning is illegal in most jurisdictions and violates bug bounty programme terms. The authors are not responsible for misuse, damage, or legal consequences arising from use of this tool.
