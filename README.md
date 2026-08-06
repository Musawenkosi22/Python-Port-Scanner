# Simple Network Scanner

A lightweight, multithreaded TCP port scanner built in Python for learning
network security fundamentals. Built as part of hands on cybersecurity
practice using Kali Linux.

## Features

- Scans a target host across a custom port range (e.g. `1-1024`, `22,80,443`)
- Multithreaded for fast scans across large port ranges
- Basic banner grabbing to identify running services
- Optional plain text report output
- Simple, dependency free  uses only Python's standard library

## Requirements

- Python 3.6+
- No external packages required

## Usage

```bash
python3 scanner.py -t <target> -p <port_range> [-o report.txt]
```

### Examples

Scan the first 1024 ports on a target:
```bash
python3 scanner.py -t 192.168.1.10 -p 1-1024
```

Scan specific ports and save a report:
```bash
python3 scanner.py -t scanme.nmap.org -p 20-25,80,443 -o results.txt
```

Adjust thread count and timeout for speed vs. accuracy:
```bash
python3 scanner.py -t 192.168.1.10 -p 1-65535 --threads 200 --timeout 0.3
```

### Options

| Flag          | Description                                      | Default |
|---------------|---------------------------------------------------|---------|
| `-t, --target`| Target IP address or hostname (required)          | —       |
| `-p, --ports` | Port(s) to scan, e.g. `1-1024` or `22,80,443`      | `1-1024`|
| `-o, --output`| Path to save a plain text report                  | none    |
| `--threads`   | Number of worker threads                           | `100`   |
| `--timeout`   | Socket timeout in seconds                           | `1.5`   |

## How it works

The scanner resolves the target hostname to an IP, builds a queue of ports
to check, and spins up worker threads that attempt a TCP connection to
each port (`connect_ex`). If the connection succeeds, it's marked open,
and the scanner attempts to read a short banner from the service (many
services announce themselves on connection, e.g. SSH or FTP).

This is a simplified version of what tools like `nmap` do under the hood —
built from scratch to understand sockets, threading, and TCP scanning at
a fundamental level.

Legal & Ethical Use

This tool is for educational purposes and authorized security testing
**only**. Only scan systems you own or have explicit written permission
to test (e.g. `scanme.nmap.org`, which Nmap's maintainers provide
specifically for testing scanners like this one, or your own local
network/lab VMs).

Scanning systems without authorization may violate computer misuse laws
in your country, regardless of intent.

## Project background

Built while studying BCom Information Systems & Technology, as a
practical introduction to networking and security concepts alongside
coursework using Kali Linux.

## License

MIT
