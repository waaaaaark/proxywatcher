"""
Standalone DNS monitor.
Listens on UDP 53 on the lab interface, logs all queries,
flags suspicious domains, and forwards to INetSim on localhost.
"""

import json
import math
import re
import socket
import threading
import urllib.request
from datetime import datetime

from dnslib import DNSRecord
from dnslib.server import DNSServer, BaseResolver, DNSLogger

BACKEND_URL    = "http://localhost:8000/alerts"
INETSIM_HOST   = "10.10.10.1"
INETSIM_PORT   = 53
BIND_HOST      = "10.10.10.1"
BIND_PORT      = 5353   # we'll redirect 53 -> 5353 via iptables

DGA_TLDS       = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click"}
SAFE_APEX      = {"google.com", "cloudflare.com", "amazonaws.com", "microsoft.com",
                  "ubuntu.com", "canonical.com"}

def entropy(s):
    if not s: return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f/n) * math.log2(f/n) for f in freq.values())

def analyze(domain):
    domain = domain.rstrip(".")
    parts  = domain.split(".")
    apex   = ".".join(parts[-2:]) if len(parts) >= 2 else domain
    tld    = "." + parts[-1] if len(parts) > 1 else ""
    flags  = []

    if apex in SAFE_APEX:
        return []

    if tld in DGA_TLDS:
        flags.append(f"suspicious_tld:{tld}")

    for label in parts[:-1]:
        e = entropy(label)
        if e > 3.5 and len(label) > 8:
            flags.append(f"high_entropy_label:{label[:20]}({e:.2f})")

    if len(domain) > 50:
        flags.append(f"long_domain:{len(domain)}_chars")

    if re.search(r"\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}", domain):
        flags.append("ip_pattern_in_domain")

    subdomain_count = len(parts) - 2
    if subdomain_count > 4:
        flags.append(f"excessive_subdomains:{subdomain_count}")

    vowels = sum(1 for c in domain.lower() if c in "aeiou")
    if len(domain) > 8 and vowels == 0:
        flags.append("no_vowels_possible_dga")

    return flags

def post_alert(domain, flags, qtype):
    try:
        features = {
            "url":            f"dns://{domain}",
            "host":           domain,
            "method":         "DNS",
            "content_type":   f"dns/{qtype}",
            "content_length": 0,
            "flags":          flags,
            "request_headers": {},
            "response_status": None,
        }
        data = json.dumps(features).encode()
        req  = urllib.request.Request(
            BACKEND_URL, data=data,
            headers={"Content-Type": "application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=5)
        print(f"[dns_monitor] Flagged: {domain} — {flags}")
    except Exception as e:
        print(f"[dns_monitor] Post error: {e}")

class ForwardingResolver(BaseResolver):
    def resolve(self, request, handler):
        domain = str(request.q.qname).rstrip(".")
        qtype  = str(request.q.qtype)

        flags = analyze(domain)
        if flags:
            threading.Thread(target=post_alert, args=(domain, flags, qtype), daemon=True).start()

        # Forward to INetSim
        try:
            raw  = request.pack()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(raw, (INETSIM_HOST, INETSIM_PORT))
            resp_raw, _ = sock.recvfrom(4096)
            sock.close()
            return DNSRecord.parse(resp_raw)
        except Exception as e:
            print(f"[dns_monitor] Forward error: {e}")
            return request.reply()

if __name__ == "__main__":
    print(f"[dns_monitor] Listening on {BIND_HOST}:{BIND_PORT}")
    resolver = ForwardingResolver()
    logger   = DNSLogger(prefix=False)
    server   = DNSServer(resolver, port=BIND_PORT, address=BIND_HOST,
                         logger=logger, tcp=False)
    server.start()
