# 🔍 Custom Port Scanner

A fast, multithreaded port scanner with service fingerprinting, banner grabbing, and JSON/HTML report output.

## Features
- TCP & UDP scanning with multithreading
- Service fingerprinting (HTTP, SSH, FTP, SMB, etc.)
- Banner grabbing for version detection
- JSON report output
- CIDR range support

## Installation
```bash
pip install -r requirements.txt
```

## Usage
```bash
# Scan top 1024 ports
python scanner.py -t 192.168.1.1

# Scan specific ports with JSON output
python scanner.py -t 192.168.1.1 -p 22,80,443,8080 -o report.json

# Scan CIDR range
python scanner.py -t 192.168.1.0/24 -p 1-1024
```

## Legal
Use only on systems you own or have explicit permission to test.
