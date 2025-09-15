#!/bin/bash
# install_tools.sh - Install all penetration testing tools

set -e

echo "[*] Starting tool installation..."

# Create directories
mkdir -p /opt/tools/bin
mkdir -p /opt/tools/go/src
mkdir -p /opt/tools/python

# Add tools to PATH
export PATH="/opt/tools/bin:$PATH"

# Install Go tools
echo "[*] Installing Go-based tools..."

# Amass - OWASP subdomain enumeration
echo "[+] Installing Amass..."
go install -v github.com/owasp-amass/amass/v4/...@master
ln -sf $GOPATH/bin/amass /opt/tools/bin/amass

# Subfinder - Fast subdomain discovery
echo "[+] Installing Subfinder..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
ln -sf $GOPATH/bin/subfinder /opt/tools/bin/subfinder

# Assetfinder - Find related domains
echo "[+] Installing Assetfinder..."
go install github.com/tomnomnom/assetfinder@latest
ln -sf $GOPATH/bin/assetfinder /opt/tools/bin/assetfinder

# HTTPx - Fast HTTP prober
echo "[+] Installing HTTPx..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
ln -sf $GOPATH/bin/httpx /opt/tools/bin/httpx

# Nuclei - Vulnerability scanner
echo "[+] Installing Nuclei..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
ln -sf $GOPATH/bin/nuclei /opt/tools/bin/nuclei

# Katana - Web crawling framework
echo "[+] Installing Katana..."
go install github.com/projectdiscovery/katana/cmd/katana@latest
ln -sf $GOPATH/bin/katana /opt/tools/bin/katana

# FFuF - Fast web fuzzer
echo "[+] Installing FFuF..."
go install github.com/ffuf/ffuf/v2@latest
ln -sf $GOPATH/bin/ffuf /opt/tools/bin/ffuf

# GAU - Get All URLs
echo "[+] Installing GAU..."
go install github.com/lc/gau/v2/cmd/gau@latest
ln -sf $GOPATH/bin/gau /opt/tools/bin/gau

# DNSx - DNS toolkit
echo "[+] Installing DNSx..."
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
ln -sf $GOPATH/bin/dnsx /opt/tools/bin/dnsx

# Naabu - Port scanner
echo "[+] Installing Naabu..."
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
ln -sf $GOPATH/bin/naabu /opt/tools/bin/naabu

# ShuffleDNS - Wrapper for massdns
echo "[+] Installing ShuffleDNS..."
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
ln -sf $GOPATH/bin/shuffledns /opt/tools/bin/shuffledns

# GoSpider - Web spider
echo "[+] Installing GoSpider..."
go install github.com/jaeles-project/gospider@latest
ln -sf $GOPATH/bin/gospider /opt/tools/bin/gospider

# Install Python tools
echo "[*] Installing Python-based tools..."

# Sublist3r - Subdomain enumeration
echo "[+] Installing Sublist3r..."
cd /opt/tools
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r
pip3 install -r requirements.txt
ln -sf /opt/tools/Sublist3r/sublist3r.py /opt/tools/bin/sublist3r

# Subdomainizer - Find subdomains from JS files
echo "[+] Installing Subdomainizer..."
cd /opt/tools
git clone https://github.com/nsonaniya2010/SubDomainizer.git
cd SubDomainizer
pip3 install -r requirements.txt
ln -sf /opt/tools/SubDomainizer/SubDomainizer.py /opt/tools/bin/subdomainizer

# CeWL - Custom wordlist generator
echo "[+] Installing CeWL..."
cd /opt/tools
git clone https://github.com/digininja/CeWL.git
cd CeWL
gem install bundler
bundle install
ln -sf /opt/tools/CeWL/cewl.rb /opt/tools/bin/cewl

# Cloud_enum - Multi-cloud OSINT
echo "[+] Installing Cloud_enum..."
cd /opt/tools
git clone https://github.com/initstring/cloud_enum.git
cd cloud_enum
pip3 install -r requirements.txt
ln -sf /opt/tools/cloud_enum/cloud_enum.py /opt/tools/bin/cloud_enum

# Metabigor - OSINT framework
echo "[+] Installing Metabigor..."
cd /opt/tools
git clone https://github.com/j3ssie/metabigor.git
cd metabigor
go build
ln -sf /opt/tools/metabigor/metabigor /opt/tools/bin/metabigor

# Install Binary tools
echo "[*] Installing binary tools..."

# MassDNS for DNS resolution
echo "[+] Installing MassDNS..."
cd /opt/tools
git clone https://github.com/blechschmidt/massdns.git
cd massdns
make
ln -sf /opt/tools/massdns/bin/massdns /opt/tools/bin/massdns

# Install additional dependencies
echo "[*] Installing additional dependencies..."

# Nuclei templates
echo "[+] Updating Nuclei templates..."
/opt/tools/bin/nuclei -update-templates -silent

# Amass config and data files
echo "[+] Setting up Amass..."
mkdir -p /root/.config/amass
cat > /root/.config/amass/config.ini << 'EOF'
# Amass Configuration File

[scope]
# Add API keys here for better results
# shodan_api_key = YOUR_SHODAN_API_KEY
# censys_api_id = YOUR_CENSYS_API_ID  
# censys_secret = YOUR_CENSYS_SECRET

[data_sources]
# Data source specific settings

[bruteforcing]
enabled = true
recursive = true
minimum_for_recursive = 3

[alterations]
enabled = true
minimum_for_word_flip = 2
edit_distance = 1
flip_words = true
flip_numbers = true
add_words = true
add_numbers = true

[output]
minimum_sources = 2
EOF

# Create wordlists directory
echo "[+] Setting up wordlists..."
mkdir -p /opt/tools/wordlists

# Download common wordlists
cd /opt/tools/wordlists
wget -q https://github.com/danielmiessler/SecLists/archive/master.zip -O seclists.zip
unzip -q seclists.zip && rm seclists.zip
mv SecLists-master SecLists

# Download subdomain wordlists
wget -q https://raw.githubusercontent.com/rbsec/dnscan/master/subdomains-10000.txt
wget -q https://raw.githubusercontent.com/jhaddix/domain/master/bitquark_20160227_subdomains_popular_1000000.txt

# Set up API key placeholders
echo "[*] Creating API key configuration..."
cat > /opt/tools/api_keys.conf << 'EOF'
# API Keys Configuration
# Add your API keys here for enhanced reconnaissance

# Shodan
SHODAN_API_KEY=""

# Censys
CENSYS_API_ID=""
CENSYS_SECRET=""

# SecurityTrails
SECURITYTRAILS_API_KEY=""

# VirusTotal
VIRUSTOTAL_API_KEY=""

# GitHub (for GitHub recon)
GITHUB_TOKEN=""

# Facebook (for certificate transparency)
FACEBOOK_ACCESS_TOKEN=""

# Binary Edge
BINARYEDGE_API_KEY=""

# ZoomEye
ZOOMEYE_API_KEY=""

# Fofa
FOFA_EMAIL=""
FOFA_KEY=""
EOF

# Create tool configuration directory
mkdir -p /opt/tools/configs

# FFuF configuration
cat > /opt/tools/configs/ffuf_config.json << 'EOF'
{
    "rate_limit": 100,
    "delay": "200ms",
    "timeout": 10,
    "filters": {
        "status": [404, 403],
        "size": [],
        "words": [],
        "lines": []
    },
    "matchers": {
        "status": [200, 201, 202, 204, 301, 302, 307, 401, 500],
        "size": [],
        "words": [],
        "lines": []
    }
}
EOF

# Nuclei configuration
cat > /opt/tools/configs/nuclei_config.yaml << 'EOF'
# Nuclei Configuration
rate-limit: 150
bulk-size: 25
timeout: 10
retries: 1
severity: 
  - critical
  - high  
  - medium
  - low
  - info
tags:
  - exposure
  - misconfiguration
  - vulnerability
  - owasp
exclude-tags:
  - dos
  - intrusive
EOF

# HTTPx configuration
cat > /opt/tools/configs/httpx_config.yaml << 'EOF'
# HTTPx Configuration
threads: 50
timeout: 10
retries: 2
rate-limit: 150
follow-redirects: true
follow-host-redirects: true
max-redirects: 3
ports:
  - 80
  - 443
  - 8080
  - 8443
  - 8000
  - 9000
  - 3000
EOF

# Create tool wrapper scripts for better integration
echo "[*] Creating tool wrapper scripts..."

# Amass wrapper
cat > /opt/tools/bin/amass_wrapper.py << 'EOF'
#!/usr/bin/env python3
"""
Amass wrapper with enhanced configuration and output parsing
"""
import subprocess
import json
import sys
import os

def run_amass(domain, config_file=None, output_file=None):
    cmd = ['amass', 'enum', '-d', domain, '-json']
    
    if config_file and os.path.exists(config_file):
        cmd.extend(['-config', config_file])
    
    if output_file:
        cmd.extend(['-o', output_file])
    
    # Add passive mode for initial recon
    cmd.extend(['-passive', '-timeout', '30'])
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 1, "", "Amass timeout after 30 minutes"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: amass_wrapper.py <domain> [config_file] [output_file]")
        sys.exit(1)
    
    domain = sys.argv[1]
    config_file = sys.argv[2] if len(sys.argv) > 2 else None
    output_file = sys.argv[3] if len(sys.argv) > 3 else None
    
    returncode, stdout, stderr = run_amass(domain, config_file, output_file)
    
    if returncode == 0:
        print(f"Amass completed successfully for {domain}")
    else:
        print(f"Amass failed with error: {stderr}")
    
    sys.exit(returncode)
EOF
chmod +x /opt/tools/bin/amass_wrapper.py

# Nuclei wrapper with rate limiting and filtering
cat > /opt/tools/bin/nuclei_wrapper.py << 'EOF'
#!/usr/bin/env python3
"""
Nuclei wrapper with enhanced rate limiting and result filtering
"""
import subprocess
import json
import sys
import os
import time

def run_nuclei(targets_file, output_file=None, severity=None, rate_limit=150):
    cmd = ['nuclei', '-l', targets_file, '-json']
    
    if output_file:
        cmd.extend(['-o', output_file])
    
    if severity:
        cmd.extend(['-severity', severity])
    
    # Rate limiting and performance
    cmd.extend([
        '-rl', str(rate_limit),
        '-bs', '25',
        '-timeout', '10',
        '-retries', '2'
    ])
    
    # Exclude intrusive templates
    cmd.extend(['-etags', 'dos,intrusive'])
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 1, "", "Nuclei timeout after 60 minutes"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: nuclei_wrapper.py <targets_file> [output_file] [severity] [rate_limit]")
        sys.exit(1)
    
    targets_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    severity = sys.argv[3] if len(sys.argv) > 3 else "critical,high,medium"
    rate_limit = int(sys.argv[4]) if len(sys.argv) > 4 else 150
    
    returncode, stdout, stderr = run_nuclei(targets_file, output_file, severity, rate_limit)
    
    if returncode == 0:
        print(f"Nuclei scan completed successfully")
    else:
        print(f"Nuclei scan failed with error: {stderr}")
    
    sys.exit(returncode)
EOF
chmod +x /opt/tools/bin/nuclei_wrapper.py

# Create comprehensive tool testing script
cat > /opt/tools/bin/test_tools.py << 'EOF'
#!/usr/bin/env python3
"""
Test all installed penetration testing tools
"""
import subprocess
import sys
import os

tools_to_test = {
    'amass': ['amass', 'version'],
    'subfinder': ['subfinder', '-version'],
    'assetfinder': ['assetfinder', '--help'],
    'httpx': ['httpx', '-version'],
    'nuclei': ['nuclei', '-version'],
    'katana': ['katana', '-version'],
    'ffuf': ['ffuf', '-V'],
    'gau': ['gau', '--help'],
    'dnsx': ['dnsx', '-version'],
    'naabu': ['naabu', '-version'],
    'shuffledns': ['shuffledns', '-version'],
    'gospider': ['gospider', '--help'],
    'sublist3r': ['python3', '/opt/tools/bin/sublist3r', '--help'],
    'subdomainizer': ['python3', '/opt/tools/bin/subdomainizer', '--help'],
    'cloud_enum': ['python3', '/opt/tools/bin/cloud_enum', '--help'],
    'massdns': ['massdns', '--help']
}

def test_tool(tool_name, command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        if result.returncode == 0 or "help" in command or "version" in command:
            return True, "OK"
        else:
            return False, result.stderr
    except subprocess.TimeoutExpired:
        return False, "Timeout"
    except FileNotFoundError:
        return False, "Not found"
    except Exception as e:
        return False, str(e)

def main():
    print("Testing installed penetration testing tools...")
    print("=" * 50)
    
    passed = 0
    failed = 0
    
    for tool_name, command in tools_to_test.items():
        success, message = test_tool(tool_name, command)
        
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"{tool_name:<15} : {status:<8} {message}")
        
        if success:
            passed += 1
        else:
            failed += 1
    
    print("=" * 50)
    print(f"Total: {passed + failed}, Passed: {passed}, Failed: {failed}")
    
    if failed > 0:
        print(f"\nSome tools failed to install or test properly.")
        sys.exit(1)
    else:
        print(f"\nAll tools installed and tested successfully!")
        sys.exit(0)

if __name__ == "__main__":
    main()
EOF
chmod +x /opt/tools/bin/test_tools.py

# Set proper permissions
echo "[*] Setting permissions..."
chmod +x /opt/tools/bin/*
chown -R root:root /opt/tools

# Test all tools
echo "[*] Testing installed tools..."
python3 /opt/tools/bin/test_tools.py

echo "[*] Tool installation completed successfully!"
echo "[*] Tools installed in: /opt/tools/bin"
echo "[*] Configuration files in: /opt/tools/configs"
echo "[*] API keys configuration: /opt/tools/api_keys.conf"
echo "[*] Wordlists in: /opt/tools/wordlists"

# Create installation summary
cat > /opt/tools/INSTALLATION_SUMMARY.txt << 'EOF'
PENETRATION TESTING TOOLS INSTALLATION SUMMARY
==============================================

INSTALLED TOOLS:
- Amass: OWASP subdomain enumeration
- Subfinder: Fast subdomain discovery  
- Assetfinder: Related domain discovery
- HTTPx: HTTP/HTTPS probe and analysis
- Nuclei: Vulnerability scanner with templates
- Katana: Next-generation web crawler
- FFuF: Fast web fuzzer
- GAU: Get All URLs archival data
- DNSx: DNS toolkit and resolver
- Naabu: Fast port scanner
- ShuffleDNS: Wrapper around massdns for subdomain discovery
- GoSpider: Web application crawler
- Sublist3r: Python-based subdomain enumeration
- Subdomainizer: Extract subdomains from JavaScript files
- CeWL: Custom wordlist generator
- Cloud_enum: Multi-cloud OSINT tool
- Metabigor: OSINT intelligence gathering
- MassDNS: High-performance DNS resolver

DIRECTORIES:
- /opt/tools/bin: Tool executables and wrappers
- /opt/tools/configs: Tool configuration files
- /opt/tools/wordlists: Common wordlists for testing
- /opt/tools/go: Go workspace for tools

CONFIGURATION FILES:
- api_keys.conf: API key configuration template
- nuclei_config.yaml: Nuclei scanner settings
- ffuf_config.json: FFuF fuzzer configuration
- httpx_config.yaml: HTTPx probe settings

WRAPPER SCRIPTS:
- amass_wrapper.py: Enhanced Amass execution
- nuclei_wrapper.py: Rate-limited Nuclei scanning
- test_tools.py: Tool installation verification

To use tools from host containers:
docker-compose exec backend /opt/tools/bin/[tool_name]

Remember to configure API keys in /opt/tools/api_keys.conf for enhanced results!
EOF

echo "[*] Installation summary saved to: /opt/tools/INSTALLATION_SUMMARY.txt"