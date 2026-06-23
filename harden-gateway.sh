#!/bin/bash
# Run as root on the gateway VM.
# Isolates the sandbox (ens19/10.10.10.0/24) from the real internet (ens18)
# while keeping mitmproxy, dns_monitor, and INetSim functional.

set -e

SANDBOX_NET="10.10.10.0/24"
KALI="192.168.0.165"
LAN_IF="ens18"
LAB_IF="ens19"

echo "[*] Flushing existing rules..."
iptables -F
iptables -t nat -F
iptables -t mangle -F
iptables -X

echo "[*] Setting default policies: DROP everything not explicitly allowed..."
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT   # gateway itself can reach internet (needed for API enrichment)

echo "[*] Loopback..."
iptables -A INPUT -i lo -j ACCEPT

echo "[*] Established/related return traffic..."
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

echo "[*] Analyst access from kali ($KALI)..."
iptables -A INPUT -i $LAN_IF -s $KALI -p tcp --dport 22 -j ACCEPT    # SSH
iptables -A INPUT -i $LAN_IF -s $KALI -p tcp --dport 8000 -j ACCEPT  # ProxyWatcher dashboard

echo "[*] Sandbox -> gateway services..."
# DNS: sandbox sends to port 53, NAT redirects it to dns_monitor on 5353
iptables -A INPUT -i $LAB_IF -s $SANDBOX_NET -p udp --dport 5353 -j ACCEPT

# HTTP/S: sandbox sends to port 80/443, NAT redirects it to mitmproxy on 8080
iptables -A INPUT -i $LAB_IF -s $SANDBOX_NET -p tcp --dport 8080 -j ACCEPT

# INetSim: non-HTTP protocols the sandbox may try (SMTP, FTP)
# Add more ports here if INetSim is configured for them
iptables -A INPUT -i $LAB_IF -s $SANDBOX_NET -p tcp -m multiport --dports 21,25 -j ACCEPT

echo "[*] NAT redirects (restore existing)..."
iptables -t nat -A PREROUTING -i $LAB_IF -p tcp --dport 80  -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -i $LAB_IF -p tcp --dport 443 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -i $LAB_IF -p udp --dport 53  -j REDIRECT --to-port 5353

echo "[*] FORWARD chain: sandbox cannot reach real internet..."
# Nothing is explicitly allowed in FORWARD, so the DROP policy blocks everything.
# No ens19->ens18 forwarding at all.

echo "[*] IPv6: lock down completely..."
ip6tables -F
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP
ip6tables -A INPUT -i lo -j ACCEPT  # loopback only

echo "[*] Saving rules (requires iptables-persistent)..."
if [ -d /etc/iptables ]; then
    iptables-save  > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6
    echo "[+] Saved to /etc/iptables/rules.v{4,6}"
else
    echo "[!] /etc/iptables not found — install iptables-persistent to make rules survive reboot:"
    echo "    sudo apt install iptables-persistent"
    echo "    Then re-run this script."
fi

echo ""
echo "[+] Done. Verify isolation from the sandbox:"
echo "    ping 8.8.8.8          # should hang/fail"
echo "    curl http://example.com  # should get an INetSim response"
