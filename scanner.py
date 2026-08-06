#!/usr/bin/env python3
"""
Simple TCP Port Scanner
------------------------
A lightweight network scanner built for learning purposes.
Scans a target host for open TCP ports, grabs service banners
where possible, and prints/report a summary.

Usage:
    python3 scanner.py -t <target> -p <port_range> [-o report.txt]

Examples:
    python3 scanner.py -t 192.168.1.10 -p 1-1024
    python3 scanner.py -t scanme.nmap.org -p 20-25,80,443 -o results.txt

IMPORTANT: Only run this against systems you own or have explicit
written permission to test. Unauthorized scanning may be illegal.
"""

import argparse
import socket
import sys
import threading
import queue
from datetime import datetime

# Common ports mapped to typical service names, used as a fallback
# label when banner grabbing doesn't return anything.
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt",
}

print_lock = threading.Lock()
results = []  # (port, service_guess, banner)


def parse_ports(port_string):
    """Turn '1-1024,3306,8080' into a sorted list of unique ints."""
    ports = set()
    for part in port_string.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        elif part:
            ports.add(int(part))
    return sorted(ports)


def grab_banner(sock):
    """Try to read a short banner from an open socket. Returns '' on failure."""
    try:
        sock.settimeout(1)
        banner = sock.recv(1024).decode(errors="ignore").strip()
        return banner.splitlines()[0] if banner else ""
    except Exception:
        return ""


def scan_port(target, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((target, port))
        if result == 0:
            banner = grab_banner(sock)
            service = COMMON_PORTS.get(port, "unknown")
            with print_lock:
                label = banner if banner else service
                print(f"[+] Port {port:<6} OPEN   ({label})")
            results.append((port, service, banner))
    except socket.error:
        pass
    finally:
        sock.close()


def worker(target, timeout, q):
    while not q.empty():
        try:
            port = q.get_nowait()
        except queue.Empty:
            return
        scan_port(target, port, timeout)
        q.task_done()


def write_report(path, target, started, finished, ports_scanned):
    with open(path, "w") as f:
        f.write(f"Network Scan Report\n")
        f.write(f"===================\n")
        f.write(f"Target:        {target}\n")
        f.write(f"Started:       {started}\n")
        f.write(f"Finished:      {finished}\n")
        f.write(f"Ports scanned: {ports_scanned}\n")
        f.write(f"Open ports found: {len(results)}\n\n")
        if results:
            for port, service, banner in sorted(results):
                label = banner if banner else service
                f.write(f"  Port {port:<6} OPEN   ({label})\n")
        else:
            f.write("  No open ports found in the given range.\n")
    print(f"\n[*] Report saved to {path}")


def main():
    parser = argparse.ArgumentParser(
        description="A simple multithreaded TCP port scanner for learning purposes."
    )
    parser.add_argument("-t", "--target", required=True, help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", default="1-1024",
                         help="Port(s) to scan, e.g. '1-1024' or '22,80,443' (default: 1-1024)")
    parser.add_argument("-o", "--output", help="Optional path to save a text report")
    parser.add_argument("--threads", type=int, default=100, help="Number of worker threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.5, help="Socket timeout in seconds (default: 1.5)")
    args = parser.parse_args()

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[!] Could not resolve host: {args.target}")
        sys.exit(1)

    try:
        ports = parse_ports(args.ports)
    except ValueError:
        print("[!] Invalid port range format. Use e.g. '1-1024' or '22,80,443'.")
        sys.exit(1)

    print(f"[*] Scanning target: {args.target} ({target_ip})")
    print(f"[*] Port range: {args.ports} ({len(ports)} ports)")
    print(f"[*] Threads: {args.threads}\n")

    q = queue.Queue()
    for port in ports:
        q.put(port)

    started = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    threads = []
    for _ in range(min(args.threads, len(ports)) or 1):
        t = threading.Thread(target=worker, args=(target_ip, args.timeout, q))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    finished = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"\n[*] Scan complete. {len(results)} open port(s) found.")

    if args.output:
        write_report(args.output, f"{args.target} ({target_ip})", started, finished, args.ports)


if __name__ == "__main__":
    main()
