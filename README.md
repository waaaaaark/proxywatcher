# ProxyWatcher

An AI-powered network threat detection platform built for hands-on malware analysis. ProxyWatcher intercepts HTTP/S and DNS traffic in an isolated Proxmox lab, extracts and analyzes suspicious files and domains, and uses Claude to triage every alert with a severity score, plain-English explanation, and recommended action — all surfaced in a real-time SOC-style dashboard.

This project was built to simulate the workflow of a SOC analyst and malware analyst: traffic interception, static file analysis, threat intelligence enrichment, and case management, end to end.

## Why

Most "malware analysis" portfolio projects are upload-a-file-and-analyze-it tools. ProxyWatcher instead runs continuously at the network level, the way real detection tooling does — inspecting every request that crosses a controlled boundary rather than waiting for a file to be handed to it.

## Architecture

```
┌─────────────┐     ┌──────────────────────────────────┐     ┌──────────────────┐
│   sandbox   │────▶│             gateway              │────▶│   INetSim        │
│ (isolated   │     │  mitmproxy → interceptor.py       │     │  (simulated      │
│  VM, no     │     │  dns_monitor.py                   │     │   internet)      │
│  real       │     │  FastAPI + SQLite + WebSocket     │     │                  │
│  internet)  │     │  YARA · oletools · pdfminer       │     └──────────────────┘
└─────────────┘     │  VirusTotal · AbuseIPDB           │
                     │  Claude API triage                │
                     └──────────────────┬─────────────────┘
                                        │
                                        ▼
                              ┌──────────────────┐
                              │  Live dashboard   │
                              │  (case mgmt,      │
                              │   filters,        │
                              │   bulk actions)    │
                              └──────────────────┘
```

Three network zones, isolated with Proxmox virtual bridges:

- **Sandbox VM** — where suspicious files are opened and malware is detonated. No route to the real internet; all traffic is forced through the gateway via `iptables`.
- **Gateway VM** — runs every ProxyWatcher service. Acts as a transparent man-in-the-middle for both HTTP/S (via `mitmproxy`) and DNS (via a custom forwarding resolver), and routes "internet" traffic to `INetSim`, which fakes DNS/HTTP/SMTP responses so malware behaves as if it has real connectivity.
- **Analyst machine** — connects to the dashboard over an SSH tunnel. Never touches the sandbox or malware directly.

## Features

**Traffic interception**
- Transparent HTTP/S interception via `mitmproxy`, with a custom addon that extracts features from every flagged flow
- Standalone DNS monitor (pure Python, `dnslib`) — flags DGA-style domains using Shannon entropy, suspicious TLDs, excessive subdomain counts, and DNS-tunneling patterns

**Static analysis**
- Office macro extraction (`oletools` / `olevba`) — pulls and inspects VBA macros from intercepted `.docm`/`.xlsm`/`.pptm` files
- PDF analysis (`pdfminer`) — extracts text, flags embedded JavaScript and embedded files
- JavaScript obfuscation detection — flags `eval()`, `unescape()`, hex-encoded strings, and other common obfuscation patterns
- YARA scanning — 279+ rules from the [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) community ruleset, compiled once at startup and run against every suspicious file

**Threat intelligence enrichment**
- VirusTotal — file hash and domain reputation lookups
- AbuseIPDB — IP reputation and abuse confidence scoring

**AI triage**
- Every alert (HTTP, DNS, or file-based) is sent to Claude along with all extracted features and enrichment data
- Claude returns a severity rating (`low` / `medium` / `high` / `critical`), a plain-English summary of why the alert fired, and a recommended action (`monitor` / `investigate` / `block`)

**Dashboard**
- Real-time alert feed over WebSocket
- Case management: status workflow (`unassigned` → `open` → `investigating` → `closed`), analyst assignment, closing reasons, and a notes thread per alert
- Filtering by severity, status, recommended action, and free-text search
- Bulk actions for multi-alert status changes
- JSON/CSV export
- Keyboard shortcuts (`/` to search, `Esc` to close detail panel)

## Stack

| Layer | Technology |
|---|---|
| Traffic interception | mitmproxy (Python addon API) |
| DNS monitoring | Custom resolver built on `dnslib` |
| Static analysis | `oletools`, `pdfminer.six`, `yara-python` |
| Backend | FastAPI, `aiosqlite`, WebSocket |
| AI triage | Claude API (Anthropic) |
| Threat intel | VirusTotal API, AbuseIPDB API |
| Frontend | Vanilla JS, no build step |
| Infrastructure | Proxmox, isolated virtual bridges, `iptables`, INetSim |

## Setup

This project assumes a Proxmox host with two VMs already provisioned: a **gateway** VM (runs all services, has one NIC on the real network and one on an isolated bridge) and a **sandbox** VM (isolated, no real internet, routes everything through the gateway).

### 1. Clone and install dependencies

```bash
git clone https://github.com/yourusername/proxywatcher.git
cd proxywatcher
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

`mitmproxy`, `oletools`, `pdfminer.six`, `yara-python`, and `dnslib` need to be installed against your system Python (the one `mitmdump` actually runs under), not just the venv:

```bash
/usr/bin/python3.10 -m pip install mitmproxy oletools pdfminer.six yara-python dnslib
```

### 2. Pull the YARA ruleset

```bash
mkdir -p yara-rules
cd yara-rules
git clone --depth=1 https://github.com/Neo23x0/signature-base.git
cd ..
```

### 3. Set environment variables

```bash
export ANTHROPIC_API_KEY="your-key-here"
export VIRUSTOTAL_API_KEY="your-key-here"
export ABUSEIPDB_API_KEY="your-key-here"
```

VirusTotal and AbuseIPDB are free tier and optional — the app degrades gracefully without them.

### 4. Configure your network

Set up two Proxmox virtual bridges: one with a real uplink (analyst/gateway traffic) and one isolated bridge with no uplink (gateway ↔ sandbox traffic only). Configure `iptables` on the gateway to:
- Redirect sandbox port 80/443 → mitmproxy (8080)
- Redirect sandbox port 53 → the DNS monitor (5353)
- NAT outbound gateway traffic so the sandbox's "internet" is fully simulated by INetSim

### 5. Run it

```bash
./run.sh
```

This starts the FastAPI backend, mitmproxy, and the DNS monitor together. The dashboard is served at `http://localhost:8000`.

### 6. Access the dashboard remotely

From your analyst machine:

```bash
ssh -L 8001:localhost:8000 user@gateway-ip
```

Then open `http://localhost:8001`.

## Safety notes

This project is designed to run malware in a fully isolated environment. Before running real samples:

- Take a Proxmox snapshot of the sandbox VM before every detonation, and revert after
- Confirm the sandbox VM has no route to your real network (verify with the verification steps below)
- Source samples only from reputable repositories (e.g. MalwareBazaar) and handle them with care, especially self-propagating or destructive payloads

Verify isolation from the sandbox VM:

```bash
nslookup google.com        # should resolve via INetSim, not real DNS
curl --max-time 5 https://google.com   # should time out — no real internet
```

## Roadmap

- Correlation rules (multi-alert pattern detection across a time window)
- Beaconing detection (timing-based C2 identification)
- GeoIP enrichment
- Alert suppression / tuning rules
- Automated response (auto-block via `iptables` on critical alerts)

## License

MIT
