"""
proxywatcher - correlation engine

Detects patterns *across* multiple alerts from the same host, which a single
alert in isolation cannot reveal:

  - alert_burst : one host produces many alerts in a short window
  - escalation  : one host produces several high/critical alerts
  - beaconing   : one host makes repeated connections at regular intervals
                  (low timing jitter -> possible C2 callback)

Correlations are persisted in their own table and de-duplicated: as more alerts
arrive for a host that is already correlated, the existing open correlation is
updated (its contributing alert list grows) rather than a new one being created.

Each evaluation returns a list of (event_name, correlation_dict) tuples so the
caller (main.py) can broadcast them over the WebSocket using the standard
{"event": ..., "data": ...} envelope.
"""

import json
import statistics
from datetime import datetime, timedelta

import aiosqlite

# --- Tunables (kept here so they're easy to adjust per-lab) ---

# alert_burst: N alerts from one host within this many minutes
BURST_WINDOW_MIN = 10
BURST_THRESHOLD = 5

# escalation: N high/critical alerts from one host within this many minutes
ESCALATION_WINDOW_MIN = 30
ESCALATION_THRESHOLD = 2

# beaconing: regular-interval repeated connections
BEACON_WINDOW_MIN = 60
BEACON_MIN_HITS = 4          # need at least this many requests to judge timing
BEACON_MIN_INTERVAL_SEC = 5  # ignore rapid-fire bursts (those are alert_burst)
BEACON_MAX_CV = 0.20         # coefficient of variation of intervals must be <= this

# An open correlation older than this (no new alerts) is considered stale and a
# fresh one is started instead of extending it.
CORRELATION_STALE_MIN = 60

SEVERITY_RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
RANK_SEVERITY = {v: k for k, v in SEVERITY_RANK.items()}


# --- Schema ---

async def init_corr_db(db: aiosqlite.Connection) -> None:
    await db.execute("""
        CREATE TABLE IF NOT EXISTS correlations (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at  TEXT NOT NULL,
            updated_at  TEXT NOT NULL,
            rule        TEXT NOT NULL,
            host        TEXT NOT NULL,
            severity    TEXT NOT NULL,
            title       TEXT NOT NULL,
            description TEXT NOT NULL,
            alert_ids   TEXT NOT NULL,
            alert_count INTEGER NOT NULL,
            status      TEXT NOT NULL DEFAULT 'open',
            raw         TEXT NOT NULL
        )
    """)
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_corr_host_rule ON correlations(host, rule)")
    await db.commit()


# --- Helpers ---

def _parse_ts(iso: str) -> datetime:
    # alerts store created_at as datetime.utcnow().isoformat() (naive, no tz)
    return datetime.fromisoformat(iso.replace("Z", ""))

def _max_severity(severities: list[str]) -> str:
    rank = max((SEVERITY_RANK.get((s or "unknown").lower(), 0) for s in severities), default=0)
    return RANK_SEVERITY.get(rank, "unknown")

def _bump_severity(sev: str, floor: str) -> str:
    return _max_severity([sev, floor])


async def _recent_alerts_for_host(db, host, window_min):
    """Alerts for a host within the window, oldest-first."""
    since = (datetime.utcnow() - timedelta(minutes=window_min)).isoformat()
    db.row_factory = aiosqlite.Row
    cur = await db.execute(
        "SELECT id, created_at, severity, flags FROM alerts "
        "WHERE host = ? AND created_at >= ? ORDER BY created_at ASC",
        (host, since))
    return [dict(r) for r in await cur.fetchall()]


# --- Rules: each returns a detection dict or None ---

def _rule_alert_burst(host, alerts):
    cutoff = datetime.utcnow() - timedelta(minutes=BURST_WINDOW_MIN)
    window = [a for a in alerts if _parse_ts(a["created_at"]) >= cutoff]
    if len(window) < BURST_THRESHOLD:
        return None
    ids = [a["id"] for a in window]
    sev = _bump_severity(_max_severity([a["severity"] for a in window]), "high")
    span = _parse_ts(window[-1]["created_at"]) - _parse_ts(window[0]["created_at"])
    span_min = max(1, round(span.total_seconds() / 60))
    return {
        "rule": "alert_burst",
        "host": host,
        "severity": sev,
        "title": f"Alert burst from {host}",
        "description": (f"{len(window)} alerts from {host} within {span_min} min "
                        f"(threshold {BURST_THRESHOLD}/{BURST_WINDOW_MIN} min)."),
        "alert_ids": ids,
        "raw": {"count": len(window), "window_min": BURST_WINDOW_MIN, "span_min": span_min},
    }


def _rule_escalation(host, alerts):
    cutoff = datetime.utcnow() - timedelta(minutes=ESCALATION_WINDOW_MIN)
    window = [a for a in alerts
              if _parse_ts(a["created_at"]) >= cutoff
              and SEVERITY_RANK.get((a["severity"] or "unknown").lower(), 0) >= SEVERITY_RANK["high"]]
    if len(window) < ESCALATION_THRESHOLD:
        return None
    ids = [a["id"] for a in window]
    sev = _bump_severity(_max_severity([a["severity"] for a in window]), "critical")
    return {
        "rule": "escalation",
        "host": host,
        "severity": sev,
        "title": f"Repeated high-severity activity from {host}",
        "description": (f"{len(window)} high/critical alerts from {host} within "
                        f"{ESCALATION_WINDOW_MIN} min."),
        "alert_ids": ids,
        "raw": {"count": len(window), "window_min": ESCALATION_WINDOW_MIN},
    }


def _rule_beaconing(host, alerts):
    cutoff = datetime.utcnow() - timedelta(minutes=BEACON_WINDOW_MIN)
    window = [a for a in alerts if _parse_ts(a["created_at"]) >= cutoff]
    if len(window) < BEACON_MIN_HITS:
        return None
    times = [_parse_ts(a["created_at"]) for a in window]
    intervals = [(times[i] - times[i - 1]).total_seconds() for i in range(1, len(times))]
    # Drop rapid-fire intervals — those are bursts, not regular beacons.
    intervals = [iv for iv in intervals if iv >= BEACON_MIN_INTERVAL_SEC]
    if len(intervals) < BEACON_MIN_HITS - 1:
        return None
    mean = statistics.fmean(intervals)
    if mean <= 0:
        return None
    cv = statistics.pstdev(intervals) / mean
    if cv > BEACON_MAX_CV:
        return None
    ids = [a["id"] for a in window]
    sev = _bump_severity(_max_severity([a["severity"] for a in window]), "high")
    period = round(mean)
    return {
        "rule": "beaconing",
        "host": host,
        "severity": sev,
        "title": f"Regular beaconing to {host}",
        "description": (f"{len(window)} connections to {host} at a regular ~{period}s "
                        f"interval (jitter {cv*100:.0f}%) — possible C2 callback."),
        "alert_ids": ids,
        "raw": {"count": len(window), "period_sec": period,
                "cv": round(cv, 3), "intervals_sec": [round(i) for i in intervals]},
    }


RULES = [_rule_alert_burst, _rule_escalation, _rule_beaconing]


# --- Persistence / de-duplication ---

async def _upsert(db, detection):
    """Insert a new correlation, or extend the matching open one.

    Returns (event_name, correlation_row_dict), or None when an existing
    correlation already covered every contributing alert (nothing to broadcast).
    """
    now = datetime.utcnow().isoformat()
    stale_before = (datetime.utcnow() - timedelta(minutes=CORRELATION_STALE_MIN)).isoformat()
    db.row_factory = aiosqlite.Row
    cur = await db.execute(
        "SELECT * FROM correlations WHERE host = ? AND rule = ? AND status = 'open' "
        "AND updated_at >= ? ORDER BY id DESC LIMIT 1",
        (detection["host"], detection["rule"], stale_before))
    existing = await cur.fetchone()

    ids = sorted(set(detection["alert_ids"]))

    if existing:
        prev = sorted(set(json.loads(existing["alert_ids"])))
        merged = sorted(set(prev) | set(ids))
        if merged == prev:
            # Nothing new contributed — don't churn / re-broadcast.
            return None
        sev = _bump_severity(existing["severity"], detection["severity"])
        await db.execute(
            "UPDATE correlations SET updated_at = ?, severity = ?, description = ?, "
            "alert_ids = ?, alert_count = ?, raw = ? WHERE id = ?",
            (now, sev, detection["description"], json.dumps(merged), len(merged),
             json.dumps(detection["raw"]), existing["id"]))
        await db.commit()
        cur = await db.execute("SELECT * FROM correlations WHERE id = ?", (existing["id"],))
        return ("correlation_updated", dict(await cur.fetchone()))

    cur = await db.execute(
        "INSERT INTO correlations "
        "(created_at, updated_at, rule, host, severity, title, description, "
        " alert_ids, alert_count, status, raw) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)",
        (now, now, detection["rule"], detection["host"], detection["severity"],
         detection["title"], detection["description"], json.dumps(ids), len(ids),
         json.dumps(detection["raw"])))
    await db.commit()
    cur = await db.execute("SELECT * FROM correlations WHERE id = ?", (cur.lastrowid,))
    return ("correlation_new", dict(await cur.fetchone()))


async def evaluate_host(db: aiosqlite.Connection, host: str) -> list[tuple[str, dict]]:
    """Run all correlation rules for a host and persist any detections.

    Degrades gracefully: any rule error is swallowed so a correlation failure
    never blocks the alert pipeline.
    """
    if not host:
        return []
    events = []
    try:
        # Pull one window large enough for every rule, then let each rule slice
        # the part it needs.
        alerts = await _recent_alerts_for_host(
            db, host, max(BURST_WINDOW_MIN, ESCALATION_WINDOW_MIN, BEACON_WINDOW_MIN))
        for rule in RULES:
            try:
                detection = rule(host, alerts)
            except Exception as e:
                print(f"[correlation] rule {rule.__name__} error: {e}")
                continue
            if not detection:
                continue
            result = await _upsert(db, detection)
            if result:
                events.append(result)
    except Exception as e:
        print(f"[correlation] evaluate_host error: {e}")
    return events
