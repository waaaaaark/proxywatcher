import fnmatch
import yara
import glob
import math
import string
import json
import re
import tempfile
import os
import sys
import urllib.request
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import enrichment

from mitmproxy import http
# Compile YARA rules once at module load
YARA_RULES = None
YARA_RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "yara-rules", "signature-base", "yara")
YARA_RULE_CATEGORIES = [
    "malware_*",
    "exploit_*", 
    "gen_*",
    "crime_*",
]

def load_yara_rules():
    global YARA_RULES
    compiled = {}
    skipped = 0
    all_files = glob.glob(os.path.join(YARA_RULES_DIR, "*.yar"))
    
    # Only load files matching our categories
    selected = []
    for path in all_files:
        basename = os.path.basename(path).lower()
        if any(glob.fnmatch.fnmatch(basename, pat) for pat in YARA_RULE_CATEGORIES):
            selected.append(path)
    
    print(f"[proxywatcher] YARA: compiling {len(selected)} selected rulesets...")
    for path in selected:
        name = os.path.basename(path).replace(".yar","").replace("-","_").replace(".","_")
        try:
            compiled[name] = yara.compile(filepath=path)
        except Exception:
            skipped += 1
    
    YARA_RULES = compiled
    print(f"[proxywatcher] YARA: loaded {len(compiled)} rulesets ({skipped} skipped)")

load_yara_rules()
BACKEND_URL = "http://localhost:8000/alerts"

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".ps1", ".vbs", ".js",
    ".docm", ".xlsm", ".pptm", ".pdf", ".zip", ".iso",
}

OFFICE_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".doc", ".xls", ".ppt"}
PDF_EXTENSIONS = {".pdf"}
JS_EXTENSIONS = {".js"}

SUSPICIOUS_PATTERNS = [
    r"[a-z0-9]{20,}\.(tk|ml|ga|cf|gq)$",
    r"\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}",
    r"(payload|malware|c2|beacon|stage\d)",
]

OBFUSCATION_PATTERNS = [
    r"eval\s*\(",
    r"unescape\s*\(",
    r"fromCharCode",
    r"String\.fromCharCode",
    r"\\x[0-9a-fA-F]{2}",
]


def extract_office_macros(data: bytes, filename: str) -> dict:
    """Write to temp file and run olevba on it."""
    result = {"has_macros": False, "macro_content": "", "suspicious_keywords": []}
    try:
        from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML
        with tempfile.NamedTemporaryFile(suffix=filename, delete=False) as f:
            f.write(data)
            tmp_path = f.name
        try:
            vba = VBA_Parser(tmp_path)
            if vba.detect_vba_macros():
                result["has_macros"] = True
                code_parts = []
                for (_, _, vba_filename, code) in vba.extract_macros():
                    code_parts.append(f"--- {vba_filename} ---\n{code}")
                result["macro_content"] = "\n".join(code_parts)[:3000]
                result["suspicious_keywords"] = vba.detect_vba_macros() and [
                    kw for (_, _, kw, _) in vba.analyze_macros()
                ] or []
        finally:
            os.unlink(tmp_path)
    except Exception as e:
        result["error"] = str(e)
    return result


def extract_pdf_info(data: bytes) -> dict:
    """Extract text and javascript from a PDF."""
    result = {"text_sample": "", "has_javascript": False, "has_embedded_files": False}
    try:
        from pdfminer.high_level import extract_text
        import io
        text = extract_text(io.BytesIO(data))
        result["text_sample"] = text[:2000]
        result["has_javascript"] = "/JavaScript" in data.decode("latin-1", errors="ignore")
        result["has_embedded_files"] = "/EmbeddedFile" in data.decode("latin-1", errors="ignore")
    except Exception as e:
        result["error"] = str(e)
    return result


def check_js_obfuscation(data: bytes) -> dict:
    """Look for obfuscation patterns in JavaScript."""
    result = {"obfuscation_patterns": [], "sample": ""}
    try:
        text = data[:5000].decode("utf-8", errors="ignore")
        result["sample"] = text[:1000]
        for pattern in OBFUSCATION_PATTERNS:
            if re.search(pattern, text):
                result["obfuscation_patterns"].append(pattern)
    except Exception as e:
        result["error"] = str(e)
    return result
def run_yara(data: bytes) -> list[str]:
    if not YARA_RULES or not data:
        return []
    hits = []
    try:
        for name, rules in YARA_RULES.items():
            matches = rules.match(data=data)
            for m in matches:
                hits.append(m.rule)
                if len(hits) >= 10:
                    return hits
    except Exception as e:
        print(f"[proxywatcher] YARA scan error: {e}")
    return hits
def extract_features(flow: http.HTTPFlow) -> dict | None:
    url = flow.request.pretty_url
    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or ""
    content_type = flow.response.headers.get("content-type", "") if flow.response else ""
    content_length = int(flow.response.headers.get("content-length", 0)) if flow.response else 0

    flags = []
    extra = {}

    # Extension check
    ext = ""
    for e in SUSPICIOUS_EXTENSIONS:
        if path.lower().endswith(e):
            ext = e
            flags.append(f"suspicious_extension:{e}")
            break

    # Host pattern check
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, host, re.IGNORECASE):
            flags.append(f"suspicious_host_pattern:{pattern}")

    # Large binary
    if content_length > 5_000_000 and "octet-stream" in content_type:
        flags.append("large_binary_download")

    if flow.response and flow.response.content:
        body = flow.response.content
        body_sample = body[:2048].decode("utf-8", errors="ignore")

        # Base64 density
        b64_ratio = len(re.findall(r"[A-Za-z0-9+/=]{40,}", body_sample))
        if b64_ratio > 3:
            flags.append("high_base64_density")
	# YARA scan on suspicious files
        if ext or "octet-stream" in content_type:
            yara_hits = run_yara(body)
            if yara_hits:
                flags.append(f"yara_match:{','.join(yara_hits)}")
                extra["yara_matches"] = yara_hits
        # Office macro extraction
        if any(path.lower().endswith(e) for e in OFFICE_EXTENSIONS):
            macro_info = extract_office_macros(body, os.path.basename(path) or "file.doc")
            if macro_info.get("has_macros"):
                flags.append("contains_vba_macros")
            extra["office_analysis"] = macro_info

        # PDF analysis
        elif any(path.lower().endswith(e) for e in PDF_EXTENSIONS):
            pdf_info = extract_pdf_info(body)
            if pdf_info.get("has_javascript"):
                flags.append("pdf_contains_javascript")
            if pdf_info.get("has_embedded_files"):
                flags.append("pdf_has_embedded_files")
            extra["pdf_analysis"] = pdf_info

        # JavaScript obfuscation
        elif any(path.lower().endswith(e) for e in JS_EXTENSIONS) or "javascript" in content_type:
            js_info = check_js_obfuscation(body)
            if js_info.get("obfuscation_patterns"):
                flags.append(f"js_obfuscation:{','.join(js_info['obfuscation_patterns'])}")
            extra["js_analysis"] = js_info

    if not flags:
        return None

    return {
        "url": url,
        "host": host,
        "method": flow.request.method,
        "content_type": content_type,
        "content_length": content_length,
        "flags": flags,
        "request_headers": dict(flow.request.headers),
        "response_status": flow.response.status_code if flow.response else None,
        **extra,
    }


def post_alert(features: dict) -> None:
    try:
        data = json.dumps(features).encode("utf-8")
        req = urllib.request.Request(
            BACKEND_URL,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        print(f"[proxywatcher] Failed to post alert: {e}")
def calculate_entropy(domain: str) -> float:
    """Shannon entropy — high entropy = random-looking = possible DGA."""
    if not domain:
        return 0.0
    freq = {}
    for c in domain:
        freq[c] = freq.get(c, 0) + 1
    length = len(domain)
    return -sum((f/length) * math.log2(f/length) for f in freq.values())


DGA_SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click"}
KNOWN_SAFE_DOMAINS  = {"google.com", "cloudflare.com", "amazonaws.com", "microsoft.com"}

def analyze_domain(domain: str) -> list[str]:
    """Return list of flags for a queried domain."""
    flags = []
    domain = domain.rstrip(".")
    parts  = domain.split(".")
    tld    = "." + parts[-1] if len(parts) > 1 else ""
    subdomain_count = len(parts) - 2

    # Skip obviously safe domains
    apex = ".".join(parts[-2:]) if len(parts) >= 2 else domain
    if apex in KNOWN_SAFE_DOMAINS:
        return []

    # Suspicious free TLDs
    if tld in DGA_SUSPICIOUS_TLDS:
        flags.append(f"suspicious_tld:{tld}")

    # High entropy label — possible DGA
    for label in parts[:-1]:
        entropy = calculate_entropy(label)
        if entropy > 3.5 and len(label) > 8:
            flags.append(f"high_entropy_label:{label[:20]} ({entropy:.2f})")

    # Very long domain
    if len(domain) > 50:
        flags.append(f"long_domain:{len(domain)}_chars")

    # IP address in domain (fast flux / typosquatting)
    if re.search(r"\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}", domain):
        flags.append("ip_pattern_in_domain")

    # Excessive subdomains (DNS tunneling often uses many labels)
    if subdomain_count > 4:
        flags.append(f"excessive_subdomains:{subdomain_count}")

    # High consonant ratio — gibberish detector
    consonants = sum(1 for c in domain.lower() if c in "bcdfghjklmnpqrstvwxyz")
    vowels     = sum(1 in [c in "aeiou"] for c in domain.lower())
    if len(domain) > 6 and vowels == 0:
        flags.append("no_vowels_possible_dga")

    return flags

class ProxyWatcher:
    def response(self, flow: http.HTTPFlow) -> None:
        features = extract_features(flow)
        if features:
            print(f"[proxywatcher] Flagged: {features['url']} — {features['flags']}")
            body = flow.response.content if flow.response else b""
            ioc_data = enrichment.enrich(features, body)
            if ioc_data:
                features["enrichment"] = ioc_data
                if ioc_data.get("vt_malicious", 0) > 0:
                    features["flags"].append(f"vt_malicious:{ioc_data['vt_malicious']}/{ioc_data.get('vt_total', 0)}")
                if ioc_data.get("vt_domain_malicious", 0) > 0:
                    features["flags"].append(f"vt_domain_malicious:{ioc_data['vt_domain_malicious']}/{ioc_data.get('vt_domain_total', 0)}")
                if ioc_data.get("abuse_confidence", 0) > 25:
                    features["flags"].append(f"abuseipdb_confidence:{ioc_data['abuse_confidence']}%")
            post_alert(features)

    def dns_request(self, flow) -> None:
        """Called for every DNS query from the sandbox."""
        try:
            for question in flow.request.questions:
                domain = str(question.name)
                flags  = analyze_domain(domain)
                if flags:
                    features = {
                        "url":     f"dns://{domain}",
                        "host":    domain,
                        "method":  "DNS",
                        "content_type": "dns/query",
                        "content_length": 0,
                        "flags":   flags,
                        "request_headers": {},
                        "response_status": None,
                        "dns_query_type": str(question.type),
                    }
                    ioc_data = enrichment.enrich(features)
                    if ioc_data:
                        features["enrichment"] = ioc_data
                        if ioc_data.get("vt_domain_malicious", 0) > 0:
                            features["flags"].append(f"vt_domain_malicious:{ioc_data['vt_domain_malicious']}")
                        if ioc_data.get("abuse_confidence", 0) > 25:
                            features["flags"].append(f"abuseipdb_confidence:{ioc_data['abuse_confidence']}%")
                    print(f"[proxywatcher] DNS flag: {domain} — {features['flags']}")
                    post_alert(features)
        except Exception as e:
            print(f"[proxywatcher] DNS handler error: {e}")

addons = [ProxyWatcher()]
