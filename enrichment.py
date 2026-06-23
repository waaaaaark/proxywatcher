"""
IOC enrichment module.
Looks up IPs, domains, and file hashes against VirusTotal and AbuseIPDB.
Results are added to the features dict before Claude triage.
"""

import hashlib
import json
import os
import urllib.request
import urllib.parse

VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY  = os.environ.get("ABUSEIPDB_API_KEY", "")

VT_BASE    = "https://www.virustotal.com/api/v3"
ABUSE_BASE = "https://api.abuseipdb.com/api/v2"


def _get(url, headers):
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=8) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {"error": str(e)}


def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def vt_lookup_hash(sha256: str) -> dict:
    if not VIRUSTOTAL_API_KEY:
        return {}
    data = _get(
        f"{VT_BASE}/files/{sha256}",
        {"x-apikey": VIRUSTOTAL_API_KEY}
    )
    if "error" in data:
        return {"vt_error": data["error"]}
    try:
        stats = data["data"]["attributes"]["last_analysis_stats"]
        names = data["data"]["attributes"].get("names", [])[:3]
        return {
            "vt_hash":        sha256,
            "vt_malicious":   stats.get("malicious", 0),
            "vt_suspicious":  stats.get("suspicious", 0),
            "vt_total":       sum(stats.values()),
            "vt_names":       names,
        }
    except Exception:
        return {}


def vt_lookup_domain(domain: str) -> dict:
    if not VIRUSTOTAL_API_KEY:
        return {}
    data = _get(
        f"{VT_BASE}/domains/{domain}",
        {"x-apikey": VIRUSTOTAL_API_KEY}
    )
    if "error" in data:
        return {"vt_domain_error": data["error"]}
    try:
        stats = data["data"]["attributes"]["last_analysis_stats"]
        cats  = data["data"]["attributes"].get("categories", {})
        return {
            "vt_domain":           domain,
            "vt_domain_malicious": stats.get("malicious", 0),
            "vt_domain_total":     sum(stats.values()),
            "vt_categories":       list(cats.values())[:3],
        }
    except Exception:
        return {}


def vt_lookup_url(url: str) -> dict:
    if not VIRUSTOTAL_API_KEY:
        return {}
    url_id = urllib.parse.quote_plus(url)
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    data = _get(
        f"{VT_BASE}/urls/{url_id}",
        {"x-apikey": VIRUSTOTAL_API_KEY}
    )
    if "error" in data:
        return {}
    try:
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return {
            "vt_url_malicious":  stats.get("malicious", 0),
            "vt_url_suspicious": stats.get("suspicious", 0),
            "vt_url_total":      sum(stats.values()),
        }
    except Exception:
        return {}


def abuseipdb_lookup(ip: str) -> dict:
    if not ABUSEIPDB_API_KEY:
        return {}
    # Skip private/loopback IPs
    if ip.startswith(("10.", "192.168.", "127.", "172.")):
        return {}
    data = _get(
        f"{ABUSE_BASE}/check?ipAddress={ip}&maxAgeInDays=90&verbose",
        {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json",
        }
    )
    if "error" in data:
        return {"abuse_error": data["error"]}
    try:
        d = data["data"]
        return {
            "abuse_confidence": d.get("abuseConfidenceScore", 0),
            "abuse_total_reports": d.get("totalReports", 0),
            "abuse_country":    d.get("countryCode", ""),
            "abuse_isp":        d.get("isp", ""),
            "abuse_domain":     d.get("domain", ""),
            "abuse_last_seen":  d.get("lastReportedAt", ""),
        }
    except Exception:
        return {}


def enrich(features: dict, body: bytes = None) -> dict:
    """
    Main entry point. Takes a features dict and optional response body.
    Returns enrichment dict to merge into features before Claude triage.
    """
    enrichment = {}

    host = features.get("host", "")
    url  = features.get("url", "")

    # Domain lookup
    if host and not host.replace(".", "").isdigit():
        enrichment.update(vt_lookup_domain(host))

    # IP lookup — extract from host if it looks like an IP
    if host and host.replace(".", "").isdigit():
        enrichment.update(abuseipdb_lookup(host))

    # File hash lookup
    if body and len(body) > 0:
        sha256 = hash_bytes(body)
        enrichment["file_sha256"] = sha256
        vt_result = vt_lookup_hash(sha256)
        if vt_result:
            enrichment.update(vt_result)

    return enrichment
