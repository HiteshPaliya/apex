# Apex v4.1

Automated bug bounty reconnaissance and attack orchestration toolkit for Kali Linux and WSL2.

## 🚀 Overview

Apex is a high-performance scanning engine that automates the transition from subdomain discovery to vulnerability exploitation. It intelligently decides which tools to run based on the detected technology stack of each target.

## ✨ Key Features

- **Multi-Phase Pipeline:** Automated Recon, Discovery, Vulnerability Scanning, and Injection testing.
- **Smart Decision Tree:** Intelligently selects runners (e.g., WPScan for WordPress, JWTRunner if tokens found).
- **WAF Awareness:** Automatically detects WAFs and adjusts scan rates and rotates headers for evasion.
- **Scope Enforcement:** Supports `scope.txt` with wildcard patterns to prevent out-of-scope scanning.
- **Confidence Scoring:** Findings are ranked by confidence (`certain`, `firm`, `tentative`) to reduce noise.
- **Real-time Notifications:** Support for Discord/Slack webhooks for critical and high-severity findings.
- **OOB Integration:** Native support for `interactsh` for blind vulnerability detection.
- **Performance Optimized:** Parallel host scanning with $O(1)$ state lookups.

## 🛠️ Installation

```bash
chmod +x install.sh
./install.sh
source ~/.bashrc
```

## ⚙️ Configuration

You can configure API keys (Shodan, VirusTotal, etc.) and global settings in `~/.apex_config.yaml`.

```yaml
# Example ~/.apex_config.yaml
api_keys:
  shodan: "YOUR_KEY"
  virustotal: "YOUR_KEY"
webhook_url: "https://discord.com/api/webhooks/..."
```

## 📖 Usage

### Basic Scan
```bash
python3 apex.py -t example.com
```

### Full Scan with OOB and Scope
```bash
python3 apex.py -t example.com --oob --scope scope.txt
```

### Options
- `-t, --target`: Target domain.
- `--oob`: Enable interactsh for blind detection.
- `--scope`: Path to `scope.txt`.
- `--webhook`: Webhook URL for notifications.
- `--min-confidence`: Filter findings by confidence (`certain`, `firm`, `tentative`).
- `--resume`: Resume an interrupted scan.
- `--phase`: Run specific phase (`recon`, `discover`, `vuln`, `inject`, `special`).

## ⚠️ Disclaimer

This tool is intended for use by security professionals and authorized bug bounty hunters. **Only scan targets you have explicit written permission to test.** The authors are not responsible for misuse or damage caused by this tool.
