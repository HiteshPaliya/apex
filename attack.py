#!/usr/bin/env python3
"""
Apex v4.1 — PART 2: Attack + Apex
============================================================
Combine with core.py to produce the full apex:
    cat core.py attack.py > apex.py
    python3 apex.py -t example.com

This file assumes all classes from core.py are already defined.
"""

import argparse
import fnmatch
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import urllib.parse
import concurrent.futures
from pathlib import Path
from typing import Optional

# ══════════════════════════════════════════════════════════════
# 10. NUCLEI RUNNER  (per-host, tag-set driven)
# ══════════════════════════════════════════════════════════════

class NucleiRunner(BaseRunner):
    """
    9000+ template vulnerability scanner.
    Tag set is chosen per-host by DecisionTree based on fingerprinted tech.
    Output is streamed line-by-line — never buffered in RAM.
    """
    NAME = "nuclei"
    CATEGORY = "vuln"

    SEV_MAP = {
        "critical": "critical", "high": "high",
        "medium":   "medium",   "low":  "low",
        "info":     "info",     "unknown": "info",
    }
    TID_TO_CID = {
        "exposed-git":            "in2/r8",
        "exposed-env-file":       "in1",
        "php-info":               "in7",
        "swagger":                "ap12",
        "graphql-introspection":  "ap1",
        "jwt-none-alg":           "a10",
        "cors-misconfig":         "z12",
        "ssrf":                   "ss1",
        "xss":                    "x1",
        "sqli":                   "i1",
        "default-login":          "a5",
        "spring-actuator":        "ms10",
        "wp-user-enum":           "a1",
        "laravel-debug":          "lv1",
        "firebase-db-access":     "gcp11",
        "s3-bucket-public":       "aws1",
        "kubernetes-api-server":  "k1",
        "docker-api-unauth":      "in10",
        "jenkins-unauth":         "in11",
        "elasticsearch-unauth":   "in8",
        "redis-unauth":           "in8",
        "mongodb-unauth":         "in8",
    }

    def run(self, tags: list = None) -> list:
        if not self.registry.has("nuclei"):
            log("nuclei not found", "skip", self.NAME)
            return self._local

        all_tags = tags or ["misconfig", "exposure", "cve", "tech"]
        out_json = self.out / "nuclei_results.json"

        cmd = [
            self.registry.path("nuclei"),
            "-u",           self.base_url,
            "-json-export", str(out_json),
            "-tags",        ",".join(sorted(set(all_tags))),
            "-severity",    "critical,high,medium,low,info",
            "-rate-limit",  str(min(self.rate_limit, 150)),
            "-concurrency", "25",
            "-timeout",     "10",
            "-retries",     "1",
            "-no-httpx",
            "-silent",      "-no-color",
            "-H", f"X-Forwarded-For: {self._random_ip()}",
        ] + self.auth_args

        if self.oob.domain:
            cmd += ["-iserver", self.oob.domain]

        for line in self.stream_cmd(cmd, timeout=1800):
            try:
                d    = json.loads(line)
                tid  = d.get("template-id", "")
                name = d.get("info", {}).get("name", tid)
                sev  = self.SEV_MAP.get(
                    d.get("info", {}).get("severity", "info"), "info")
                mat  = d.get("matched-at", self.base_url)
                det  = ", ".join(d.get("extracted-results", []) or [])
                cid  = next((v for k, v in self.TID_TO_CID.items()
                             if k in tid), f"nuclei/{tid}")
                
                # Confidence: high severity findings from nuclei are usually firm
                conf = "firm" if sev in ("critical", "high") else "tentative"
                self.add(cid, f"[nuclei] {name}", sev, conf, det or mat, mat)
            except Exception:
                pass

        log(f"{len(self._local)} findings", "ok", self.NAME, self.host)
        return self._local

# ══════════════════════════════════════════════════════════════
# 11. INJECTION RUNNERS  (per-host)
# ══════════════════════════════════════════════════════════════

class GFFilterRunner(BaseRunner):
    """
    Aggregates param URLs from all sources for this host,
    then uses gf to categorise them into injection-type buckets
    (sqli, xss, ssrf, lfi, ssti, idor, rce, redirect).
    Downstream runners read these files instead of all URLs.
    """
    NAME = "gf_filter"
    CATEGORY = "inject"

    PATTERNS = {
        "sqli":     "i1",   "xss":      "x1",
        "ssrf":     "ss1",  "redirect": "adv6",
        "lfi":      "f10",  "ssti":     "i10",
        "idor":     "z1",   "rce":      "i8",
    }

    def run(self) -> list:
        all_urls = self._collect()
        if not all_urls:
            return self._local

        urls_file = self.out / "all_urls.txt"
        urls_file.write_text("\n".join(all_urls))
        log(f"Filtering {len(all_urls)} URLs with gf",
            "info", self.NAME, self.host)

        if not self.registry.has("gf"):
            log("gf not found — skipping pattern filter", "skip", self.NAME)
            return self._local

        for pattern, cid in self.PATTERNS.items():
            out_file = self.out / f"{pattern}_urls.txt"
            try:
                proc = subprocess.run(
                    [self.registry.path("gf"), pattern],
                    input="\n".join(all_urls),
                    capture_output=True, text=True, timeout=30)
                matches = [u.strip() for u in proc.stdout.splitlines()
                           if u.strip()]
                if matches:
                    out_file.write_text("\n".join(matches))
                    self.add(cid, f"gf({pattern}): {len(matches)} candidate URLs", "info", "tentative",
                             f"URLs with potential {pattern.upper()} params",
                             "\n".join(matches[:5]))
            except subprocess.TimeoutExpired:
                pass
            except Exception as e:
                log(f"gf {pattern} error: {e}", "warn", self.NAME)
        return self._local

    def _collect(self) -> list:
        urls: set = set()
        # From checkpoint (populated by katana + arjun + paramspider)
        for u in self.ckpt.get("param_urls", []):
            if self.host in u:
                urls.add(u)
        # From gau output for this host
        gau_file = (self.out.parent.parent / "gau" /
                    self.host.replace(":", "_") / "all_urls.txt")
        if gau_file.exists():
            for u in gau_file.read_text().splitlines():
                if u.strip() and "?" in u:
                    urls.add(u.strip())
        return list(urls)

    def pattern_file(self, pattern: str) -> Optional[Path]:
        p = self.out / f"{pattern}_urls.txt"
        return p if p.exists() and p.stat().st_size > 0 else None


class SqlmapRunner(BaseRunner):
    """i1-i5 — SQL injection with sqlmap on gf-filtered URLs."""
    NAME = "sqlmap"
    CATEGORY = "inject"

    def run(self) -> list:
        if not self.registry.has("sqlmap"):
            log("sqlmap not found", "skip", self.NAME)
            return self._local

        gf_dir = (self.out.parent.parent / "gf_filter" /
                  self.host.replace(":", "_"))
        sqli_f = gf_dir / "sqli_urls.txt"
        raw_urls = ([u for u in sqli_f.read_text().splitlines() if u.strip()]
                    if sqli_f.exists() else [f"{self.base_url}/?id=1"])

        urls = self._dedup_by_path(raw_urls)
        log(f"{len(raw_urls)} URLs → {len(urls)} unique paths after dedup",
            "info", self.NAME, self.host)

        sql_dir = self.out / "sqlmap_data"
        sql_dir.mkdir(exist_ok=True)

        for url in urls[:15]:
            cmd = [
                self.registry.path("sqlmap"),
                "-u", url, "--batch", "--random-agent",
                "--level", "3", "--risk", "2",
                "--output-dir", str(sql_dir),
                "--forms",
                "--crawl",    "0",
                "--smart",
                "--time-sec", "10",
                "--timeout", "15", "--retries", "1",
                "--threads", "3", "--flush-session",
                "--headers", f"X-Forwarded-For: {self._random_ip()}",
            ]
            if self.opts.get("cookie"):
                cmd += ["--cookie", self.opts["cookie"]]
            if self.opts.get("bearer"):
                cmd += ["--headers",
                        f"Authorization: Bearer {self.opts['bearer']}"]
            if self.oob.domain:
                cmd += ["--dns-domain", self.oob.domain]

            vuln_lines: list = []
            for line in self.stream_cmd(cmd, timeout=600):
                if any(kw in line.lower() for kw in [
                    "is vulnerable", "identified the following",
                    "injectable", "payload:", "time-based blind",
                    "boolean-based blind", "error-based",
                    "union query", "stacked queries",
                ]):
                    vuln_lines.append(line.strip())

            if vuln_lines:
                inj = next(
                    (t for t in ["time-based", "boolean-based",
                                 "error-based", "union"]
                     if any(t in v.lower() for v in vuln_lines)),
                    "unknown")
                cid = {"time-based": "i3", "boolean-based": "i2",
                       "error-based": "i1"}.get(inj, "i1")
                self.add(cid, f"SQL injection ({inj}): {url}", "critical", "certain",
                         "\n".join(vuln_lines[:5]), url,
                         "Use parameterized queries / prepared statements")
        return self._local

    @staticmethod
    def _dedup_by_path(urls: list) -> list:
        seen_paths: set  = set()
        deduped:    list = []
        for url in urls:
            try:
                path = urllib.parse.urlparse(url).path
                if path not in seen_paths:
                    seen_paths.add(path)
                    deduped.append(url)
            except Exception:
                deduped.append(url)
        return deduped


class DalfoxRunner(BaseRunner):
    """x1-x3, x8 — XSS scanning with dalfox + blind OOB."""
    NAME = "dalfox"
    CATEGORY = "inject"

    def run(self) -> list:
        if not self.registry.has("dalfox"):
            log("dalfox not found", "skip", self.NAME)
            return self._local

        gf_dir = (self.out.parent.parent / "gf_filter" /
                  self.host.replace(":", "_"))
        xss_f  = gf_dir / "xss_urls.txt"
        urls   = ([u for u in xss_f.read_text().splitlines() if u.strip()][:50]
                  if xss_f.exists() else [self.base_url])

        urls_file = self.out / "targets.txt"
        urls_file.write_text("\n".join(urls))

        cmd = [
            self.registry.path("dalfox"),
            "file",       str(urls_file),
            "--format",   "json",
            "--no-color", "--silence",
            "--timeout",  "10",
            "--delay",    str(max(1000 // self.rate_limit, 10)),
            "--worker",   "20",
            "--custom-header", f"X-Forwarded-For: {self._random_ip()}",
        ]
        if self.opts.get("cookie"):
            cmd += ["--cookie", self.opts["cookie"]]
        if self.opts.get("bearer"):
            cmd += ["--custom-header",
                    f"Authorization: Bearer {self.opts['bearer']}"]
        blind_url = self.oob.probe_url("dalfox-blind", "Dalfox blind XSS")
        if blind_url:
            cmd += ["--blind", blind_url]

        for line in self.stream_cmd(cmd, timeout=900):
            try:
                d      = json.loads(line)
                xurl   = d.get("param", d.get("url", ""))
                xtype  = d.get("type", "xss").lower()
                payload = d.get("payload", "")
                cid    = ("x8" if "blind" in xtype else
                          "x3" if "dom"   in xtype else "x1")
                conf   = "certain" if "blind" in xtype else "firm"
                self.add(cid, f"XSS ({xtype}): {xurl}", "high", conf,
                         f"Payload: {payload[:120]}", xurl,
                         "Encode output; implement strict CSP")
            except Exception:
                pass
        return self._local


class SSRFRunner(BaseRunner):
    """ss1-ss12 — SSRF via param injection + OOB callbacks + SSRFmap."""
    NAME = "ssrf"
    CATEGORY = "inject"

    URL_PARAMS = [
        "url", "callback", "webhook", "redirect", "next", "return",
        "link", "src", "href", "fetch", "import", "proxy", "remote",
        "host", "dest", "uri", "resource", "target", "image", "file",
    ]
    IMDS_INDICATORS = [
        "ami-id", "instance-id", "security-credentials",
        "meta-data", "computeMetadata", "identity/oauth2",
    ]

    def run(self) -> list:
        gf_dir = (self.out.parent.parent / "gf_filter" /
                  self.host.replace(":", "_"))
        ssrf_f = gf_dir / "ssrf_urls.txt"
        urls   = ([u for u in ssrf_f.read_text().splitlines() if u.strip()][:30]
                  if ssrf_f.exists() else [self.base_url])

        oob_probe = self.oob.probe_url("ssrf-probe", f"SSRF on {self.host}")
        payloads = [p for p in [
            oob_probe,
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/metadata/instance",
            "http://0x7f000001/",
            "http://[::1]/",
            "dict://127.0.0.1:6379/info",
        ] if p is not None]

        for base_url in urls[:15]:
            parsed = urllib.parse.urlparse(base_url)
            params = list(urllib.parse.parse_qs(parsed.query).keys())

            for param in (params or self.URL_PARAMS[:8]):
                for pl in payloads[:3]:
                    test = self._inject(base_url, param, pl)
                    r    = self.http(test, timeout=8)
                    if r and r["status"] == 200:
                        if any(ind in r["body"]
                               for ind in self.IMDS_INDICATORS):
                            self.add("ss2", f"SSRF→IMDS via param '{param}'", "critical", "certain",
                                     f"Cloud metadata returned via ?{param}=",
                                     f"{test}\n{r['body'][:300]}")

        # SSRFmap (if installed and OOB is active)
        oob_lhost = self.oob.probe_url("ssrfmap", "SSRFmap probe")
        if SSRFMAP.exists() and ssrf_f and ssrf_f.exists() and oob_lhost:
            for line in self.stream_cmd([
                "python3", str(SSRFMAP),
                "-r", str(ssrf_f), "-p", "url", "--lhost", oob_lhost,
                "-m", "readfiles,networkscan,alibaba,aws,gcp,azure",
            ], timeout=180):
                if "ssrf" in line.lower() and "found" in line.lower():
                    self.add("ss1", f"SSRFmap: {line[:100]}", "high", "firm", line[:200])
        return self._local

    def _inject(self, url: str, param: str, value: str) -> str:
        p  = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(p.query, keep_blank_values=True)
        qs[param] = [value]
        return urllib.parse.urlunparse(
            p._replace(query=urllib.parse.urlencode(qs, doseq=True)))


class CrlfuzzRunner(BaseRunner):
    """i18 — CRLF injection scanning with crlfuzz."""
    NAME = "crlfuzz"
    CATEGORY = "inject"

    def run(self) -> list:
        if not self.registry.has("crlfuzz"):
            log("crlfuzz not found", "skip", self.NAME)
            return self._local
        for line in self.stream_cmd([
            self.registry.path("crlfuzz"),
            "-u", self.base_url, "-s",
        ], timeout=180):
            if "vuln" in line.lower() or "crlfound" in line.lower():
                self.add("i18", f"CRLF injection: {line[:100]}", "high", "firm",
                         "CRLF enables header injection / response splitting",
                         line)
        return self._local


class CorsyRunner(BaseRunner):
    """z12, z13 — CORS misconfiguration via Corsy or manual probes."""
    NAME = "corsy"
    CATEGORY = "inject"

    ORIGINS = [
        "https://evil.com",
        "null",
        "https://evil.{host}",
        "https://{host}.evil.com",
    ]

    def run(self) -> list:
        return self._run_corsy() if CORSY.exists() else self._manual()

    def _run_corsy(self) -> list:
        tf  = self.out / "targets.txt"
        tf.write_text(self.base_url)
        out = self.out / "corsy_results.json"
        h   = "User-Agent: Mozilla/5.0"
        if self.opts.get("cookie"):
            h += f"\nCookie: {self.opts['cookie']}"
        for _ in self.stream_cmd([
            "python3", str(CORSY),
            "-i", str(tf), "-o", str(out), "-t", "20", "--headers", h,
        ], timeout=180):
            pass
        if out.exists():
            try:
                for url, issues in json.loads(out.read_text()).items():
                    for issue, detail in issues.items():
                        sev = ("critical"
                               if "credential" in str(detail).lower()
                               else "high")
                        self.add("z12", f"CORS: {issue}", sev, "firm",
                                 str(detail)[:200], url)
            except Exception:
                pass
        return self._local

    def _manual(self) -> list:
        for path in ["/api/user", "/api/me", "/"]:
            for tmpl in self.ORIGINS:
                origin = tmpl.format(host=self.host)
                r = self.http(path, headers={"Origin": origin})
                if not r:
                    continue
                h    = {k.lower(): v for k, v in r["headers"].items()}
                acao = h.get("access-control-allow-origin", "")
                acac = h.get("access-control-allow-credentials", "")
                if acao in (origin, "*") or (
                        origin == "null" and acao == "null"):
                    sev = ("critical" if acac.lower() == "true"
                           else "medium")
                    cid = "z13" if origin == "null" else "z12"
                    self.add(cid, f"CORS: {origin} reflected", sev, "firm",
                             f"ACAO: {acao}, ACAC: {acac}",
                             f"Origin: {origin} → {acao}")
        return self._local

# ══════════════════════════════════════════════════════════════
# 12. SPECIALISED RUNNERS
# ══════════════════════════════════════════════════════════════

class JWTRunner(BaseRunner):
    """a9-a13, oa21-oa25 — Full JWT attack suite via jwt_tool."""
    NAME = "jwt"
    CATEGORY = "special"

    JWT_RE = re.compile(
        r'(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{0,})')

    def run(self) -> list:
        token = self._find_token()
        if not token:
            log("No JWT found to test", "skip", self.NAME, self.host)
            return self._local
        self._inspect(token)
        if JWT_TOOL.exists():
            self._jwt_tool_attacks(token)
        return self._local

    def _find_token(self) -> Optional[str]:
        for src in [self.opts.get("bearer", ""),
                    str(self.opts.get("cookie", ""))]:
            m = self.JWT_RE.search(src)
            if m:
                return m.group(1)
        for path in ["/", "/api/user", "/api/me"]:
            r = self.http(path)
            if r:
                m = self.JWT_RE.search(r["body"] + str(r["headers"]))
                if m:
                    return m.group(1)
        return None

    def _inspect(self, token: str):
        try:
            parts   = token.split(".")
            pad     = lambda s: s + "=" * (4 - len(s) % 4)
            header  = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
            payload = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
            alg = header.get("alg", "")
            kid = header.get("kid", "")
            jku = header.get("jku") or header.get("x5u")
            exp = payload.get("exp", 0)

            if alg.lower() == "none":
                self.add("a10", "JWT uses 'none' algorithm", "critical", "certain",
                         "No signature — token forgeable without a key",
                         json.dumps(header))
            if alg.upper().startswith("RS"):
                self.add("a9", f"JWT RS-family ({alg}) — RS256→HS256 possible", "critical", "firm",
                         "Sign with server public key as HMAC secret",
                         f"alg: {alg}")
            if kid:
                self.add("a11", f"JWT kid: '{kid}'", "high", "tentative",
                         "Test: kid='../../dev/null', kid=1 OR 1=1 (SQLi)",
                         f"kid: {kid}")
            if jku:
                self.add("a13", f"JWT jku/x5u: {jku}", "critical", "certain",
                         "Replace jku with attacker-controlled JWK Set URL",
                         jku)
            if exp and (exp - time.time()) > 86400 * 30:
                self.add("a12", "JWT expiry > 30 days", "medium", "firm",
                         f"Valid for {(exp - time.time())/86400:.0f} more days",
                         str(exp))
            if exp and time.time() > exp:
                self.add("a12", "Expired JWT — test if server still accepts it", "high", "firm",
                         "Probe server-side exp validation", str(exp))
        except Exception as e:
            log(f"JWT decode error: {e}", "warn", self.NAME)

    def _jwt_tool_attacks(self, token: str):
        test_url = self.opts.get("jwt_endpoint",
                                  f"{self.base_url}/api/user")
        out_file = self.out / "jwt_tool_results.txt"
        cmd = ["python3", str(JWT_TOOL), token,
               "-t", test_url, "-M", "at", "-rc"]
        if self.opts.get("cookie"):
            cmd += ["-rh", f"Cookie: {self.opts['cookie']}"]

        lines: list = []
        for line in self.stream_cmd(cmd, timeout=300):
            lines.append(line)
        out_file.write_text("\n".join(lines))
        full = "\n".join(lines)

        for pat, cid, title, sev in [
            (r"(?i)CRITICAL.*none",      "a10", "JWT none alg accepted",   "critical"),
            (r"(?i)CRITICAL.*alg.*conf", "a9",  "JWT alg confusion",       "critical"),
            (r"(?i)CRITICAL.*kid.*path", "a11", "JWT kid path traversal",  "critical"),
            (r"(?i)CRITICAL.*kid.*sql",  "a11", "JWT kid SQL injection",   "critical"),
            (r"(?i)CRITICAL.*jku",       "a13", "JWT jku injection",       "critical"),
            (r"(?i)expired.*accept",     "a12", "Expired JWT accepted",    "high"),
        ]:
            if re.search(pat, full):
                self.add(cid, f"[jwt_tool] {title}", sev, "certain",
                         "jwt_tool confirmed vulnerability", full[:400])


class SmugglerRunner(BaseRunner):
    """c4, c5, c6 — HTTP request smuggling via smuggler.py."""
    NAME = "smuggler"
    CATEGORY = "special"

    def run(self) -> list:
        if not SMUGGLER.exists():
            log("smuggler.py not installed", "skip", self.NAME)
            return self._local
        out_file = self.out / "smuggler_results.txt"
        lines: list = []
        for line in self.stream_cmd([
            "python3", str(SMUGGLER),
            "--url", self.base_url,
            "--log", str(out_file),
            "--timeout", "10",
            "--schemes", "https,http",
        ], timeout=300):
            lines.append(line)
        combined = "\n".join(lines)
        if out_file.exists():
            combined += "\n" + out_file.read_text()
        for marker, cid, title, sev in [
            ("CL.TE",            "c4", "HTTP smuggling CL.TE",  "critical"),
            ("TE.CL",            "c5", "HTTP smuggling TE.CL",  "critical"),
            ("CL.0",             "c4", "HTTP smuggling CL.0",   "high"),
            ("HTTP/2 downgrade", "c6", "HTTP/2 smuggling",      "critical"),
        ]:
            if (marker.lower() in combined.lower()
                    and "vulnerable" in combined.lower()):
                self.add(cid, title, sev, "certain",
                         "smuggler.py confirmed desync vulnerability",
                         combined[:500])
        return self._local


class NiktoRunner(BaseRunner):
    """General-purpose web server security scanner."""
    NAME = "nikto"
    CATEGORY = "special"

    def run(self) -> list:
        if not self.registry.has("nikto"):
            log("nikto not found", "skip", self.NAME)
            return self._local
        cmd = [
            self.registry.path("nikto"),
            "-h",        self.base_url,
            "-maxtime",  "300",
            "-Tuning",   "013456789abcde",
            "-nointeractive",
        ]
        if self.opts.get("cookie"):
            cmd += ["-cookies", self.opts["cookie"]]
        for line in self.stream_cmd(cmd, timeout=400):
            if "+ " in line and "OSVDB" not in line:
                sev = ("high" if any(w in line.lower() for w in
                                     ["sql", "xss", "rce", "injection",
                                      "bypass", "overflow", "remote",
                                      "shell"]) else "low")
                self.add("nikto", f"[nikto] {line[2:80]}", sev, "firm", line[:200])
        return self._local


class WpscanRunner(BaseRunner):
    """wp1-wp13 — WordPress vulnerability scanning."""
    NAME = "wpscan"
    CATEGORY = "special"

    def run(self) -> list:
        if not self.registry.has("wpscan"):
            log("wpscan not found", "skip", self.NAME)
            return self._local
        out_json = self.out / "wpscan_results.json"
        cmd = [
            self.registry.path("wpscan"),
            "--url",               self.base_url,
            "--output",            str(out_json),
            "--format",            "json",
            "--enumerate",         "u,p,vp,vt,tt,cb,dbe",
            "--plugins-detection", "aggressive",
            "--no-banner",
        ]
        if os.environ.get("WPSCAN_API_TOKEN"):
            cmd += ["--api-token", os.environ["WPSCAN_API_TOKEN"]]
        if self.opts.get("cookie"):
            cmd += ["--cookie", self.opts["cookie"]]

        for _ in self.stream_cmd(cmd, timeout=600):
            pass

        if not out_json.exists():
            return self._local
        try:
            data = json.loads(out_json.read_text())
            for uname in data.get("users", {}):
                self.add("a1", f"WordPress user: {uname}", "medium", "certain",
                         "WPScan user enumeration", uname)
            for plugin, pd in data.get("plugins", {}).items():
                for vuln in pd.get("vulnerabilities", []):
                    score = vuln.get("cvss", {}).get("score", 5)
                    sev   = ("critical" if score >= 9 else
                             "high"     if score >= 7 else "medium")
                    self.add("wp1", f"WP plugin vuln: {vuln.get('title','')}", sev, "firm",
                             f"Plugin: {plugin}  CVSS: {score}",
                             str(vuln.get("references", {}))[:200])
            for vuln in data.get("version", {}).get("vulnerabilities", []):
                self.add("wp12", f"WP core vuln: {vuln.get('title','')}", "high", "firm",
                         str(vuln.get("references", {}))[:200])
        except Exception:
            pass
        return self._local


class S3ScannerRunner(BaseRunner):
    """r16, aws1, gcp1, az1 — Cloud storage bucket enumeration."""
    NAME = "s3scanner"
    CATEGORY = "special"

    CLOUD_CHECKS = [
        ("https://{n}.s3.amazonaws.com/",
         ["ListBucketResult", "<Contents>"], "aws1"),
        ("https://storage.googleapis.com/{n}/",
         ["ListBucketResult", "<Contents>"], "gcp1"),
        ("https://{n}.blob.core.windows.net/$web"
         "?restype=container&comp=list",
         ["EnumerationResults", "<Blob>"], "az1"),
    ]

    def run(self) -> list:
        base  = self.host.replace("www.", "").split(".")[0]
        names = [base] + [f"{base}{s}" for s in
                          ["-assets", "-static", "-uploads", "-backup",
                           "-prod", "-dev", "-staging", "-data",
                           "-files", "-media", "-logs", "-config"]]

        def probe(args):
            name, tmpl, markers, cid = args
            url = tmpl.format(n=name)
            r   = self.http(url)
            if r and r["status"] == 200 and any(m in r["body"]
                                                  for m in markers):
                return name, url, cid
            return None

        tasks = [(n, tmpl, m, cid)
                 for n in names
                 for tmpl, m, cid in self.CLOUD_CHECKS]

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
            for result in pool.map(probe, tasks):
                if result:
                    name, url, cid = result
                    self.add(cid, f"Public cloud bucket: {name}", "critical", "certain",
                             f"Contents listable: {url}", url)
        return self._local

# ══════════════════════════════════════════════════════════════
# 13. DECISION TREE  (real conditional branching)
# ══════════════════════════════════════════════════════════════

class DecisionTree:
    """
    Given a per-host tech profile, returns which runners to execute
    and which nuclei tag set to use.
    """

    BASE_NUCLEI = [
        "misconfig", "exposure", "takeover", "panel",
        "default-login", "cve", "tech", "auth-bypass",
    ]

    def decide(self, host: str, profile: dict) -> dict:
        techs  = set(profile.get("tech", []))
        is_cdn = profile.get("cdn", False)

        runners: list  = []
        skipped: dict  = {}
        tags:    set   = set(self.BASE_NUCLEI)

        def add(cls, reason):  runners.append((cls, reason))
        def skip(cls, reason): skipped[cls] = reason

        # ── Discovery: always ─────────────────────────────────
        add(WafRunner,            "Always: WAF detection")
        add(NaabuRunner,          "Always: port scan")
        add(GauRunner,            "Always: historical URL collection")
        add(KatanaRunner,         "Always: active crawl + JS link extraction")
        add(GitDumperRunner,      "Always: check .git exposure")
        add(SecretJSRunner,       "Always: JS secret + endpoint extraction")
        add(FeroxbusterRunner,    "Always: directory/file brute-force")
        add(Byp4xxRunner,         "Always: 403 bypass attempts")
        add(ParamDiscoveryRunner, "Always: hidden parameter discovery")
        add(S3ScannerRunner,      "Always: cloud storage bucket enumeration")

        # ── VHost: skip on CDN (Host header meaningless) ──────
        if is_cdn:
            skip(VHostRunner, "CDN detected — vhost results unreliable")
        else:
            add(VHostRunner, "Non-CDN: virtual host discovery")

        # ── Injection: always ─────────────────────────────────
        add(GFFilterRunner,  "Always: categorise param URLs via gf")
        add(SqlmapRunner,    "Always: SQL injection on gf-filtered params")
        add(DalfoxRunner,    "Always: XSS on gf-filtered params + blind OOB")
        add(SSRFRunner,      "Always: SSRF probe + OOB callbacks")
        add(CrlfuzzRunner,   "Always: CRLF injection scan")
        add(CorsyRunner,     "Always: CORS misconfiguration")
        add(JWTRunner,       "Always: JWT analysis if any token present")

        # ── Smuggling: only if reverse proxy / CDN detected ───
        proxy_tech = {
            "nginx", "apache", "haproxy", "varnish",
            "iis", "cloudflare", "traefik", "envoy",
            "akamai", "fastly",
        }
        if techs & proxy_tech or is_cdn:
            sig = (techs & proxy_tech) or {"cdn"}
            add(SmugglerRunner,
                f"Proxy/CDN detected ({sig}): HTTP smuggling test")
            tags.add("http-request-smuggling")
        else:
            skip(SmugglerRunner, "No proxy/CDN detected — smuggling skipped")

        # ── WordPress: only if detected ───────────────────────
        if techs & {"wordpress", "wp"}:
            add(WpscanRunner, "WordPress detected — WPScan with vuln DB")
            tags |= {"wordpress"}
        else:
            skip(WpscanRunner, "WordPress not detected")

        # ── Nikto: skip on CDN (unreliable results) ───────────
        if is_cdn:
            skip(NiktoRunner, "CDN — nikto results unreliable")
        else:
            add(NiktoRunner, "Non-CDN: general nikto scan")

        # ── Nuclei tag expansion based on detected tech ───────
        tech_tag_map = {
            frozenset(["drupal"]):                          {"drupal"},
            frozenset(["joomla"]):                          {"joomla"},
            frozenset(["laravel"]):                         {"laravel", "php"},
            frozenset(["codeigniter", "symfony"]):          {"php"},
            frozenset(["django", "flask", "fastapi"]):      {"python"},
            frozenset(["spring", "tomcat", "struts",
                        "glassfish", "weblogic"]):          {"java", "spring",
                                                             "actuator", "apache"},
            frozenset(["node.js", "express",
                        "next.js", "nuxt"]):                {"node", "nodejs"},
            frozenset(["ruby", "rails"]):                   {"ruby", "rails"},
            frozenset(["php"]):                             {"php"},
            frozenset(["aws", "amazon", "s3",
                        "cloudfront"]):                     {"aws", "s3", "cloud"},
            frozenset(["firebase", "gcp", "google"]):       {"gcp", "firebase",
                                                             "cloud"},
            frozenset(["azure"]):                           {"azure", "cloud"},
            frozenset(["elasticsearch", "kibana"]):         {"elasticsearch"},
            frozenset(["redis"]):                           {"redis"},
            frozenset(["mongodb"]):                         {"mongodb"},
            frozenset(["graphql"]):                         {"graphql", "api"},
            frozenset(["swagger", "openapi"]):              {"swagger", "api"},
        }
        for tech_set, new_tags in tech_tag_map.items():
            if techs & tech_set:
                tags |= new_tags

        # Always add full injection + auth coverage
        tags |= {
            "sqli", "xss", "ssrf", "ssti", "xxe", "lfi",
            "rce", "idor", "injection", "jwt", "oauth", "saml",
        }

        return {
            "runners":      runners,
            "nuclei_tags":  sorted(tags),
            "skip_reasons": skipped,
        }

# ══════════════════════════════════════════════════════════════
# 14. REPORTER
# ══════════════════════════════════════════════════════════════

class Reporter:
    def __init__(self, target: str, out_dir: Path,
                 store: FindingStore, dec_log: dict,
                 oob: OOBManager, ckpt: Checkpoint):
        self.target  = target
        self.out_dir = out_dir
        self.store   = store
        self.dec_log = dec_log
        self.oob     = oob
        self.ckpt    = ckpt

    def write_json(self) -> Path:
        p = self.out_dir / "REPORT.json"
        p.write_text(json.dumps({
            "target":         self.target,
            "timestamp":      datetime.utcnow().isoformat(),
            "summary":        self.store.count(),
            "total":          len(self.store.all()),
            "live_hosts":     self.ckpt.get("live_hosts", []),
            "oob_callbacks":  self.oob.callbacks,
            "decision_log":   {
                h: {
                    "runners": [(r.NAME, reason)
                                for r, reason in d.get("runners", [])],
                    "skipped": {c.NAME: r
                                for c, r in d.get("skip_reasons", {}).items()},
                }
                for h, d in self.dec_log.items()
            },
            "findings":       [f.to_dict() for f in self.store.all()],
        }, indent=2))
        return p

    def write_markdown(self) -> Path:
        counts   = self.store.count()
        findings = self.store.all()
        lines    = [
            f"# Bug Bounty Report — `{self.target}`",
            f"**Date:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}  ",
            f"**Findings:** {len(findings)} (deduplicated)  ",
            f"**Hosts scanned:** {len(self.ckpt.get('live_hosts', []))}",
            "",
            "## Severity Summary",
            "| Severity | Count |",
            "|----------|------:|",
        ]
        for sev in ["critical", "high", "medium", "low", "info"]:
            n = counts.get(sev, 0)
            if n:
                lines.append(
                    f"| {C.ICON[sev]} {sev.capitalize()} | **{n}** |")

        lines += ["", "## Decision Tree Log", ""]
        for host, d in self.dec_log.items():
            lines.append(f"### `{host}`")
            for cls, reason in d.get("runners", []):
                lines.append(f"  - ✓ `{cls.NAME}` — {reason}")
            for cls, reason in d.get("skip_reasons", {}).items():
                lines.append(f"  - ✗ `{cls.NAME}` — {reason}")
            lines.append("")

        if self.oob.callbacks:
            lines += ["## OOB Callbacks (Blind Vuln Confirmations)", ""]
            for cb in self.oob.callbacks:
                lines.append(
                    f"- **{cb.get('protocol','?').upper()}** "
                    f"from `{cb.get('remote-address','?')}` "
                    f"— `{cb.get('unique-id','')}`")
            lines.append("")

        lines += ["---", "## Findings", ""]
        for sev in ["critical", "high", "medium", "low", "info"]:
            sev_f = [f for f in findings if f.severity == sev]
            if not sev_f:
                continue
            lines.append(
                f"### {C.ICON[sev]} {sev.capitalize()} ({len(sev_f)})")
            lines.append("")
            for f in sev_f:
                lines += [
                    f"#### [{f.checklist_id}] {f.title} ({f.confidence})",
                    f"**Host:** `{f.target}` | **Tool:** `{f.tool}`",
                    "", f.detail or "", "",
                ]
                if f.evidence:
                    lines += ["```", f.evidence[:600], "```", ""]
                if f.remediation:
                    lines.append(f"> **Fix:** {f.remediation}")
                lines.append("")

        p = self.out_dir / "REPORT.md"
        p.write_text("\n".join(lines))
        return p

    def print_summary(self):
        counts = self.store.count()
        hosts  = len(self.ckpt.get("live_hosts", []))
        total  = len(self.store.all())
        print(f"""
{C.GREEN}{C.BOLD}{'═'*65}
  SCAN COMPLETE — {self.target}
  {hosts} hosts scanned  ·  {total} unique findings  ·  deduplicated
{'═'*65}{C.RESET}
  🔴 Critical : {counts.get('critical', 0):>4}
  🟠 High     : {counts.get('high', 0):>4}
  🟡 Medium   : {counts.get('medium', 0):>4}
  🔵 Low      : {counts.get('low', 0):>4}
  ⚪ Info     : {counts.get('info', 0):>4}
  {'─'*30}
  OOB callbacks : {len(self.oob.callbacks):>3}
""")

# ══════════════════════════════════════════════════════════════
# 15. APEX
# ══════════════════════════════════════════════════════════════

class Apex:
    def __init__(self, args):
        self.target   = (args.target
                         .replace("https://", "").replace("http://", "")
                         .rstrip("/"))
        self.base_url = f"https://{self.target}"
        self.out_dir  = Path(args.output) / self.target.replace(".", "_")
        self.out_dir.mkdir(parents=True, exist_ok=True)

        self.opts = {
            "cookie":        args.cookie,
            "bearer":        args.bearer,
            "extra_headers": args.header or [],
            "rate_limit":    args.rate_limit,
            "phase":         args.phase,
            "workers":       args.workers,
            "oob":           args.oob,
            "webhook":       args.webhook,
            "min_conf":      args.min_confidence,
            "scope_patterns": self._load_scope(args.scope),
        }
        self.registry = ToolRegistry()
        self.oob      = OOBManager(self.registry)
        self.store    = FindingStore(webhook=args.webhook, min_conf=args.min_confidence)
        self.ckpt     = Checkpoint(self.out_dir / "checkpoint.json")
        self.tree     = DecisionTree()
        self.dec_log: dict  = {}
        self._decision_cache: dict = {}
        self._cache_lock = threading.Lock() # Fix 1

        if not args.resume and self.ckpt.path.exists():
            log("Fresh scan — clearing previous checkpoint", "info")
            self.ckpt.path.unlink()
            self.ckpt = Checkpoint(self.out_dir / "checkpoint.json")

        signal.signal(signal.SIGINT, self._on_sigint)

    def _load_scope(self, scope_path: Optional[str]) -> list:
        if not scope_path or not Path(scope_path).exists():
            return []
        return [line.strip() for line in Path(scope_path).read_text().splitlines()
                if line.strip() and not line.startswith("#")]

    def _is_in_scope(self, host: str) -> bool:
        if not self.opts["scope_patterns"]:
            return True
        return any(fnmatch.fnmatch(host, p) for p in self.opts["scope_patterns"])

    def _on_sigint(self, *_):
        print(f"\n{C.YELLOW}[!] Interrupted — checkpoint saved. "
              f"Resume with --resume{C.RESET}")
        self.ckpt.save()
        self.oob.stop()
        sys.exit(0)

    # ── factory / runner helpers ───────────────────────────────

    def _make(self, cls, host: str) -> BaseRunner:
        return cls(host, self.out_dir, self.registry,
                   self.oob, self.store, self.ckpt, self.opts)

    def _run(self, cls, host: str, skip_if_done: bool = True):
        """Run one runner on one host. Respects checkpoint."""
        if not self._is_in_scope(host):
            return
        
        if skip_if_done and self.ckpt.is_done(cls.NAME, host):
            log("Already complete — skipping", "skip", cls.NAME, host)
            return
        runner = self._make(cls, host)
        try:
            runner.run()
            runner.save_local()
            self.ckpt.mark_done(cls.NAME, host)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            log(f"Runner error: {e}", "error", cls.NAME, host)

    def _phase_ok(self, phase: str) -> bool:
        return self.opts.get("phase", "all") in ("all", phase)

    def _run_parallel(self, hosts: list, profiles: dict,
                      runner_classes: list):
        max_w = min(self.opts.get("workers", 3), max(len(hosts), 1))

        def scan_host(url: str):
            host    = urllib.parse.urlparse(url).netloc or url
            profile = profiles.get(host, profiles.get(url, {}))

            if not self._is_in_scope(host):
                return

            with self._cache_lock: # Fix 1
                if host not in self._decision_cache:
                    self._decision_cache[host] = self.tree.decide(host, profile)
                    self.dec_log[host] = self._decision_cache[host]
                decision = self._decision_cache[host]

            for cls, reason in decision["runners"]:
                if cls not in runner_classes:
                    continue
                self._run(cls, url)

        with concurrent.futures.ThreadPoolExecutor(
                max_workers=max_w) as pool:
            futures = {pool.submit(scan_host, url): url
                       for url in hosts}
            for fut in concurrent.futures.as_completed(futures):
                url = futures[fut]
                try:
                    fut.result()
                except Exception as e:
                    log(f"Host error: {e}", "error", host=url)

    def _run_nuclei_per_host(self, hosts: list, profiles: dict):
        for url in hosts:
            host    = urllib.parse.urlparse(url).netloc or url
            profile = profiles.get(host, profiles.get(url, {}))

            if not self._is_in_scope(host):
                continue

            with self._cache_lock: # Fix 1
                if host not in self._decision_cache:
                    self._decision_cache[host] = self.tree.decide(host, profile)
                    self.dec_log[host] = self._decision_cache[host]
                tags = self._decision_cache[host]["nuclei_tags"]

            if self.ckpt.is_done(NucleiRunner.NAME, url):
                log("Already done — skipping", "skip", NucleiRunner.NAME, host)
                continue

            log(f"Tags: {', '.join(tags[:8])}{'...' if len(tags)>8 else ''}",
                "info", "nuclei", host)
            runner = NucleiRunner(url, self.out_dir, self.registry,
                                  self.oob, self.store, self.ckpt, self.opts)
            runner.run(tags)
            runner.save_local()
            self.ckpt.mark_done(NucleiRunner.NAME, url)

    # ── main entry ─────────────────────────────────────────────

    def run(self):
        # Start OOB listener
        if self.opts["oob"]:
            self.oob.start(self.out_dir)

        # ── Phase 1: Subdomain recon ───────────────────────────
        if self._phase_ok("recon"):
            log("PHASE 1 — Subdomain & DNS Recon", "phase")
            self._run(SubfinderRunner, self.target)
            self._run(DNSXRunner,      self.target)

        # ── Phase 2: Fingerprint all live hosts ────────────────
        log("PHASE 2 — Live Host Fingerprinting", "phase")
        fp = self._make(HttpxFingerprintRunner, self.target)
        if not self.ckpt.is_done(HttpxFingerprintRunner.NAME, self.target):
            fp.run()
            fp.save_local()
            self.ckpt.mark_done(HttpxFingerprintRunner.NAME, self.target)

        profiles   = fp.profiles()
        live_hosts = fp.live_urls() or [self.base_url]

        for h in live_hosts:
            self.ckpt.append("live_hosts", h)
        log(f"{len(live_hosts)} live hosts to scan", "ok")

        # ── Phase 3: Per-host discovery ────────────────────────
        if self._phase_ok("discover"):
            log("PHASE 3 — Per-Host Discovery", "phase")
            self._run_parallel(live_hosts, profiles, [
                WafRunner, VHostRunner, NaabuRunner, GauRunner,
                KatanaRunner, FeroxbusterRunner, Byp4xxRunner,
                GitDumperRunner, SecretJSRunner, ParamDiscoveryRunner,
            ])

        # ── Phase 4: Nuclei (per-host, tailored tags) ─────────
        if self._phase_ok("vuln"):
            log("PHASE 4 — Vulnerability Scanning (nuclei)", "phase")
            self._run_nuclei_per_host(live_hosts, profiles)

        # ── Phase 5: Injection (per-host, parallel) ───────────
        if self._phase_ok("inject"):
            log("PHASE 5 — Injection Testing", "phase")
            self._run_parallel(live_hosts, profiles, [
                GFFilterRunner, SqlmapRunner, DalfoxRunner,
                SSRFRunner, CrlfuzzRunner, CorsyRunner,
            ])

        # ── Phase 6: Specialised (per-host, parallel) ─────────
        if self._phase_ok("special"):
            log("PHASE 6 — Specialised Attacks", "phase")
            self._run_parallel(live_hosts, profiles, [
                JWTRunner, SmugglerRunner, NiktoRunner,
                WpscanRunner, S3ScannerRunner,
            ])

        # ── Collect final OOB callbacks ────────────────────────
        if self.oob._active:
            log("Waiting 30s for final OOB callbacks...", "info", "oob")
            time.sleep(30)
            self.oob.stop()
            for cb in self.oob.callbacks:
                self.store.add(Finding(
                    "ss9/i9/i16",
                    f"OOB callback: {cb.get('protocol','?').upper()} "
                    f"from {cb.get('remote-address','?')}",
                    "high", "certain",
                    "Out-of-band interaction confirms blind SSRF/XXE/RCE",
                    json.dumps(cb)[:300],
                    "interactsh",
                    self.target,
                ))

        # ── Report ─────────────────────────────────────────────
        reporter = Reporter(self.target, self.out_dir, self.store,
                            self.dec_log, self.oob, self.ckpt)
        json_p = reporter.write_json()
        md_p   = reporter.write_markdown()
        reporter.print_summary()
        print(f"  {C.CYAN}📄 JSON : {json_p}")
        print(f"  📝 MD   : {md_p}{C.RESET}\n")

# ══════════════════════════════════════════════════════════════
# 16. ENTRY POINT
# ══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description=f"Apex v{VERSION} — Kali/WSL2",
        formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument("-t", "--target",
                        help="Target domain (e.g. example.com)")
    parser.add_argument("--cookie",
                        help="Session cookie for all requests")
    parser.add_argument("--bearer",
                        help="Bearer/JWT token for Authorization header")
    parser.add_argument("--header", action="append",
                        help="Extra header (repeatable): 'X-Foo: bar'")
    parser.add_argument("--oob", action="store_true",
                        help="Start interactsh for OOB blind detection")
    parser.add_argument("--resume", action="store_true",
                        help="Resume from checkpoint (skip completed steps)")
    parser.add_argument("--rate-limit", type=int, default=100,
                        metavar="N",
                        help="Max requests/sec per tool (default: 100)")
    parser.add_argument("--workers", type=int, default=3,
                        metavar="N",
                        help="Parallel host workers (default: 3)")
    parser.add_argument("--phase", default="all",
                        choices=["all", "recon", "discover",
                                 "vuln", "inject", "special"],
                        help="Run only one phase (default: all)")
    parser.add_argument("--output", default="./bounty_output",
                        help="Output directory (default: ./bounty_output)")
    parser.add_argument("--tools-check", action="store_true",
                        help="Print tool availability and exit")
    parser.add_argument("--scope",
                        help="Path to scope.txt (one pattern per line, e.g. *.example.com)")
    parser.add_argument("--webhook",
                        help="Discord/Slack webhook URL for critical findings")
    parser.add_argument("--min-confidence", default="tentative",
                        choices=["certain", "firm", "tentative"],
                        help="Minimum confidence level to report (default: tentative)")

    args = parser.parse_args()

    if args.tools_check:
        ToolRegistry().print_status()
        sys.exit(0)

    if not args.target:
        parser.error("-t/--target is required")

    Apex(args).run()


if __name__ == "__main__":
    main()
