#!/usr/bin/env python3
"""
Custom Port Scanner - Multithreaded TCP/UDP scanner with service fingerprinting
Author: nadirzhon | github.com/nadirzhon
"""

import socket
import argparse
import json
import threading
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init

init(autoreset=True)

COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB", 9200: "Elasticsearch"
}

lock = threading.Lock()

def grab_banner(host, port, timeout=2):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                banner = s.recv(1024).decode(errors="ignore").strip()
                return banner[:100] if banner else ""
            except Exception:
                return ""
    except Exception:
        return ""

def scan_port_tcp(host, port, timeout=1):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            service = COMMON_SERVICES.get(port, "Unknown")
            banner = grab_banner(host, port)
            return {"port": port, "protocol": "tcp", "state": "open",
                    "service": service, "banner": banner}
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None

def parse_ports(port_str):
    ports = []
    for part in port_str.split(","):
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))

def scan_host(host, ports, threads=100):
    open_ports = []
    print(f"{Fore.CYAN}[*] Scanning {host} ({len(ports)} ports)...{Style.RESET_ALL}")
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port_tcp, host, port): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
                with lock:
                    svc = result.get("service", "")
                    banner = result.get("banner", "")
                    banner_str = f" | {banner}" if banner else ""
                    print(f"  {Fore.GREEN}[+] {host}:{result['port']}/tcp - {svc}{banner_str}")
    return sorted(open_ports, key=lambda x: x["port"])

def main():
    parser = argparse.ArgumentParser(description="Custom Port Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target IP, hostname, or CIDR")
    parser.add_argument("-p", "--ports", default="1-1024", help="Ports: 22,80 or 1-1024")
    parser.add_argument("-o", "--output", help="Output JSON file")
    parser.add_argument("--threads", type=int, default=100)
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    start_time = datetime.now()
    targets = []
    try:
        network = ipaddress.ip_network(args.target, strict=False)
        targets = [str(ip) for ip in network.hosts()]
    except ValueError:
        targets = [args.target]

    all_results = []
    for target in targets:
        host_results = scan_host(target, ports, threads=args.threads)
        all_results.append({"target": target, "open_ports": host_results,
                            "scan_time": start_time.isoformat()})

    if args.output:
        with open(args.output, "w") as f:
            json.dump(all_results, f, indent=2)
        print(f"\n{Fore.YELLOW}[*] Report saved to {args.output}")

    total_open = sum(len(h["open_ports"]) for h in all_results)
    print(f"\n{Fore.CYAN}[*] Scan complete. {total_open} open ports found.")

if __name__ == "__main__":
    main()
