#!/usr/bin/env bash
# ============================================================
# Apex Installer — Kali Linux / WSL2
# Usage: chmod +x install.sh && ./install.sh
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
die()     { echo -e "${RED}[✗]${NC} $*"; exit 1; }

TOOLS_DIR="$HOME/tools"
GO_BIN="$HOME/go/bin"
mkdir -p "$TOOLS_DIR"

echo -e "${BOLD}${CYAN}"
cat << 'EOF'
  █████╗ ██████╗ ███████╗██╗  ██╗
 ██╔══██╗██╔══██╗██╔════╝╚██╗██╔╝
 ███████║██████╔╝█████╗   ╚███╔╝ 
 ██╔══██║██╔═══╝ ██╔══╝   ██╔██╗ 
 ██║  ██║██║     ███████╗██╔╝ ██╗
 ╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
  Kali Linux Apex Installer
EOF
echo -e "${NC}"

# ── Prerequisites ──────────────────────────────────────────
info "Updating apt and installing base packages..."
sudo apt-get update -qq
sudo apt-get install -y -qq \
    git curl wget python3 python3-pip python3-venv \
    golang-go ruby ruby-dev build-essential \
    libcurl4-openssl-dev libssl-dev libxml2-dev \
    nmap masscan nikto sqlmap \
    perl libwww-perl libjson-perl \
    jq unzip tar 2>/dev/null || warn "Some apt packages failed, continuing..."

# ── Go environment ──────────────────────────────────────────
info "Setting up Go environment..."
if ! command -v go &>/dev/null; then
    GO_VERSION="1.22.4"
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
    export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"
fi
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin"
mkdir -p "$GO_BIN"
success "Go $(go version | awk '{print $3}') ready"

# ── Go tools (ProjectDiscovery suite + others) ──────────────
install_go_tool() {
    local name="$1" pkg="$2"
    if command -v "$name" &>/dev/null; then
        success "$name already installed"
    else
        info "Installing $name..."
        go install -v "$pkg@latest" 2>/dev/null && success "$name installed" || warn "$name failed"
    fi
}

install_go_tool subfinder    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
install_go_tool httpx        "github.com/projectdiscovery/httpx/cmd/httpx"
install_go_tool naabu        "github.com/projectdiscovery/naabu/v2/cmd/naabu"
install_go_tool nuclei       "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
install_go_tool katana       "github.com/projectdiscovery/katana/cmd/katana"
install_go_tool dnsx         "github.com/projectdiscovery/dnsx/cmd/dnsx"
install_go_tool interactsh-client "github.com/projectdiscovery/interactsh/cmd/interactsh-client"
install_go_tool ffuf         "github.com/ffuf/ffuf/v2@latest"
install_go_tool dalfox       "github.com/hahwul/dalfox/v2@latest"
install_go_tool gau          "github.com/lc/gau/v2/cmd/gau@latest"
install_go_tool waybackurls  "github.com/tomnomnom/waybackurls@latest"
install_go_tool gf           "github.com/tomnomnom/gf@latest"
install_go_tool anew         "github.com/tomnomnom/anew@latest"
install_go_tool qsreplace    "github.com/tomnomnom/qsreplace@latest"
install_go_tool unfurl       "github.com/tomnomnom/unfurl@latest"
install_go_tool feroxbuster  "github.com/epi052/feroxbuster@latest" 2>/dev/null || \
    (info "Installing feroxbuster via curl..." && \
     curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s "$GO_BIN" 2>/dev/null || warn "feroxbuster failed")

# ── nuclei templates ────────────────────────────────────────
info "Updating nuclei templates..."
nuclei -update-templates -silent 2>/dev/null && success "Nuclei templates updated" || warn "Nuclei template update failed"

# ── gf patterns ─────────────────────────────────────────────
info "Installing gf patterns..."
mkdir -p ~/.gf
GF_PATTERNS_DIR="$TOOLS_DIR/gf-patterns"
if [ ! -d "$GF_PATTERNS_DIR" ]; then
    git clone -q https://github.com/1ndianl33t/Gf-Patterns "$GF_PATTERNS_DIR" 2>/dev/null || true
    git clone -q https://github.com/tomnomnom/gf "$TOOLS_DIR/gf-repo" 2>/dev/null || true
    cp "$TOOLS_DIR/gf-repo/examples/"*.json ~/.gf/ 2>/dev/null || true
    cp "$GF_PATTERNS_DIR/"*.json ~/.gf/ 2>/dev/null || true
    success "gf patterns installed"
fi

# ── Python tools ────────────────────────────────────────────
info "Installing Python security tools..."
pip3 install --break-system-packages --quiet \
    sqlmap \
    git-dumper \
    trufflehog \
    wafw00f \
    pyyaml \
    jwt-tool 2>/dev/null || \
pip3 install --user --quiet \
    sqlmap git-dumper trufflehog wafw00f pyyaml jwt-tool 2>/dev/null || warn "Some Python tools failed"

# jwt_tool from GitHub (more feature-complete)
if ! command -v jwt_tool &>/dev/null; then
    info "Installing jwt_tool from GitHub..."
    git clone -q https://github.com/ticarpi/jwt_tool "$TOOLS_DIR/jwt_tool" 2>/dev/null || true
    pip3 install --break-system-packages -r "$TOOLS_DIR/jwt_tool/requirements.txt" -q 2>/dev/null || true
    ln -sf "$TOOLS_DIR/jwt_tool/jwt_tool.py" /usr/local/bin/jwt_tool 2>/dev/null || \
        echo "alias jwt_tool='python3 $TOOLS_DIR/jwt_tool/jwt_tool.py'" >> ~/.bashrc
    success "jwt_tool installed"
fi

# SSRFmap
if [ ! -d "$TOOLS_DIR/SSRFmap" ]; then
    info "Installing SSRFmap..."
    git clone -q https://github.com/swisskyrepo/SSRFmap "$TOOLS_DIR/SSRFmap" 2>/dev/null
    pip3 install --break-system-packages -r "$TOOLS_DIR/SSRFmap/requirements.txt" -q 2>/dev/null || true
    success "SSRFmap installed"
fi

# smuggler (HTTP request smuggling)
if [ ! -f "$TOOLS_DIR/smuggler/smuggler.py" ]; then
    info "Installing smuggler..."
    git clone -q https://github.com/defparam/smuggler "$TOOLS_DIR/smuggler" 2>/dev/null
    success "smuggler installed"
fi

# corsy (CORS misconfiguration)
if [ ! -d "$TOOLS_DIR/Corsy" ]; then
    info "Installing Corsy..."
    git clone -q https://github.com/s0md3v/Corsy "$TOOLS_DIR/Corsy" 2>/dev/null
    pip3 install --break-system-packages -r "$TOOLS_DIR/Corsy/requirements.txt" -q 2>/dev/null || true
    success "Corsy installed"
fi

# LinkFinder (JS analysis)
if [ ! -d "$TOOLS_DIR/LinkFinder" ]; then
    info "Installing LinkFinder..."
    git clone -q https://github.com/GerbenJavado/LinkFinder "$TOOLS_DIR/LinkFinder" 2>/dev/null
    pip3 install --break-system-packages -r "$TOOLS_DIR/LinkFinder/requirements.txt" -q 2>/dev/null || true
    success "LinkFinder installed"
fi

# SecretFinder
if [ ! -d "$TOOLS_DIR/SecretFinder" ]; then
    info "Installing SecretFinder..."
    git clone -q https://github.com/m4ll0k/SecretFinder "$TOOLS_DIR/SecretFinder" 2>/dev/null
    pip3 install --break-system-packages -r "$TOOLS_DIR/SecretFinder/requirements.txt" -q 2>/dev/null || true
    success "SecretFinder installed"
fi

# crlfuzz
install_go_tool crlfuzz "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz"

# ── Go tools (additional) ───────────────────────────────────
install_go_tool gobuster "github.com/OJ/gobuster/v3@latest"

# ── Python tools (additional) ───────────────────────────────
info "Installing arjun (hidden parameter discovery)..."
pip3 install --break-system-packages --quiet arjun 2>/dev/null || \
pip3 install --user --quiet arjun 2>/dev/null || warn "arjun install failed"

info "Installing paramspider..."
if [ ! -d "$TOOLS_DIR/paramspider" ]; then
    git clone -q https://github.com/devanshbatham/ParamSpider "$TOOLS_DIR/paramspider" 2>/dev/null
    pip3 install --break-system-packages -r "$TOOLS_DIR/paramspider/requirements.txt" -q 2>/dev/null || true
    success "paramspider installed"
fi

info "Installing commix (command injection)..."
if ! command -v commix &>/dev/null; then
    sudo apt-get install -y -qq commix 2>/dev/null || \
    (git clone -q https://github.com/commixproject/commix "$TOOLS_DIR/commix" 2>/dev/null && \
     ln -sf "$TOOLS_DIR/commix/commix.py" /usr/local/bin/commix 2>/dev/null) || \
    warn "commix install failed"
else
    success "commix already installed"
fi

info "Installing byp4xx (403 bypass)..."
if [ ! -f "$TOOLS_DIR/byp4xx/byp4xx.sh" ]; then
    mkdir -p "$TOOLS_DIR/byp4xx"
    curl -sL "https://raw.githubusercontent.com/lobuhi/byp4xx/main/byp4xx.sh" \
        -o "$TOOLS_DIR/byp4xx/byp4xx.sh" 2>/dev/null && \
        chmod +x "$TOOLS_DIR/byp4xx/byp4xx.sh" && \
        success "byp4xx installed" || warn "byp4xx download failed"
fi

# ── Ruby tools ──────────────────────────────────────────────
info "Installing WPScan..."
if command -v wpscan &>/dev/null; then
    success "wpscan already installed"
else
    sudo gem install wpscan --quiet 2>/dev/null && success "wpscan installed" || warn "wpscan failed"
fi

# ── SecLists wordlists ──────────────────────────────────────
info "Installing SecLists..."
SECLISTS="/usr/share/seclists"
if [ ! -d "$SECLISTS" ]; then
    sudo git clone -q --depth=1 https://github.com/danielmiessler/SecLists "$SECLISTS" 2>/dev/null && \
        success "SecLists installed" || warn "SecLists install failed"
else
    success "SecLists already at $SECLISTS"
fi

# ── amass ───────────────────────────────────────────────────
info "Installing amass..."
if ! command -v amass &>/dev/null; then
    sudo apt-get install -y -qq amass 2>/dev/null || \
        go install -v github.com/owasp-amass/amass/v4/...@master 2>/dev/null || \
        warn "amass install failed"
else
    success "amass already installed"
fi

# ── PATH setup ──────────────────────────────────────────────
info "Updating PATH in shell configs..."
for RC in ~/.bashrc ~/.zshrc; do
    if [ -f "$RC" ]; then
        grep -q 'go/bin' "$RC" || echo 'export PATH=$PATH:$HOME/go/bin:/usr/local/go/bin' >> "$RC"
        grep -q 'tools' "$RC" || echo "export TOOLS_DIR=$HOME/tools" >> "$RC"
    fi
done

# ── Write tool paths config for Apex ────────────────────────
info "Writing tools config..."
cat > "$HOME/.apex_tools.json" << TOOLSEOF
{
  "jwt_tool":     "$TOOLS_DIR/jwt_tool/jwt_tool.py",
  "smuggler":     "$TOOLS_DIR/smuggler/smuggler.py",
  "ssrfmap":      "$TOOLS_DIR/SSRFmap/ssrfmap.py",
  "corsy":        "$TOOLS_DIR/Corsy/corsy.py",
  "linkfinder":   "$TOOLS_DIR/LinkFinder/linkfinder.py",
  "secretfinder": "$TOOLS_DIR/SecretFinder/SecretFinder.py",
  "paramspider":  "$TOOLS_DIR/paramspider/paramspider.py",
  "byp4xx":       "$TOOLS_DIR/byp4xx/byp4xx.sh",
  "seclists":     "$SECLISTS",
  "go_bin":       "$GO_BIN",
  "tools_dir":    "$TOOLS_DIR"
}
TOOLSEOF
success "Tools config written to ~/.apex_tools.json"

# ── Summary ─────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}Installation complete. Tool status:${NC}"
for tool in subfinder httpx naabu nuclei ffuf feroxbuster gobuster dalfox \
            gau waybackurls katana dnsx interactsh-client gf commix \
            sqlmap nikto wpscan amass crlfuzz arjun; do
    if command -v "$tool" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $tool"
    else
        echo -e "  ${RED}✗${NC} $tool (not in PATH)"
    fi
done

echo ""
echo -e "${CYAN}Next step:${NC}"
echo "  source ~/.bashrc"
echo "  python3 apex.py -t example.com"
echo ""
warn "Remember: Only use these tools on targets you have explicit permission to test."
