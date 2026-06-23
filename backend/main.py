"""
proxywatcher - FastAPI backend (v2)
Adds case management: status, assignment, notes, closing reasons.
"""

import asyncio
import json
import os
import sys
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Optional

import aiosqlite
import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

# Make sibling modules importable regardless of how uvicorn is launched.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import correlation

DB_PATH = os.environ.get("PROXYWATCHER_DB", "proxywatcher.db")
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
CLAUDE_MODEL = "claude-sonnet-4-6"

# --- Models ---

class AlertUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    closing_reason: Optional[str] = None
    note: Optional[str] = None

class BulkUpdate(BaseModel):
    ids: list[int]
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    closing_reason: Optional[str] = None

class CorrelationUpdate(BaseModel):
    status: Optional[str] = None  # open | acknowledged | closed

# --- Database ---

async def init_db(db: aiosqlite.Connection) -> None:
    await db.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at         TEXT NOT NULL,
            updated_at         TEXT NOT NULL,
            url                TEXT NOT NULL,
            host               TEXT NOT NULL,
            method             TEXT NOT NULL,
            flags              TEXT NOT NULL,
            severity           TEXT,
            summary            TEXT,
            recommended_action TEXT,
            raw                TEXT NOT NULL,
            status             TEXT NOT NULL DEFAULT 'unassigned',
            assigned_to        TEXT,
            closing_reason     TEXT,
            closed_at          TEXT
        )
    """)
    await db.execute("""
        CREATE TABLE IF NOT EXISTS alert_notes (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id   INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            author     TEXT NOT NULL DEFAULT 'analyst',
            body       TEXT NOT NULL,
            FOREIGN KEY (alert_id) REFERENCES alerts(id)
        )
    """)
    for col, definition in [
        ("updated_at",         "TEXT NOT NULL DEFAULT ''"),
        ("recommended_action", "TEXT"),
        ("status",             "TEXT NOT NULL DEFAULT 'unassigned'"),
        ("assigned_to",        "TEXT"),
        ("closing_reason",     "TEXT"),
        ("closed_at",          "TEXT"),
    ]:
        try:
            await db.execute(f"ALTER TABLE alerts ADD COLUMN {col} {definition}")
        except Exception:
            pass
    await db.commit()

# --- WebSocket ---

class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, event: str, data: dict) -> None:
        dead = []
        for ws in self.active:
            try:
                await ws.send_json({"event": event, "data": data})
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.active.remove(ws)

manager = ConnectionManager()

# --- Claude triage ---

async def triage_with_claude(features: dict) -> dict:
    if not ANTHROPIC_API_KEY:
        return {"severity": "unknown", "summary": "No API key configured.", "recommended_action": "investigate"}

    enrichment = features.get("enrichment", {})
    enrichment_str = ""
    if enrichment:
        enrichment_str = f"\nThreat intelligence enrichment:\n{json.dumps(enrichment, indent=2)}\n"

    prompt = f"""You are a security analyst triaging a suspicious network request caught by a MITM proxy.

Here are the extracted features:
{json.dumps(features, indent=2)}
{enrichment_str}
Respond with a JSON object containing exactly these fields:
- severity: one of "low", "medium", "high", "critical"
- summary: 2-3 sentences explaining what looks suspicious and why, incorporating any threat intel data if present
- recommended_action: one of "monitor", "investigate", "block"

Respond with only the JSON object, no other text."""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                ANTHROPIC_API_URL,
                headers={
                    "x-api-key": ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={"model": CLAUDE_MODEL, "max_tokens": 300,
                      "messages": [{"role": "user", "content": prompt}]},
                timeout=30,
            )
            data = response.json()
            text = data["content"][0]["text"]
            text = text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
            return json.loads(text)
    except Exception as e:
        return {"severity": "unknown", "summary": f"Triage error: {e}", "recommended_action": "investigate"}

# --- Helpers ---

async def get_notes(db: aiosqlite.Connection, alert_id: int) -> list[dict]:
    db.row_factory = aiosqlite.Row
    cur = await db.execute(
        "SELECT * FROM alert_notes WHERE alert_id = ? ORDER BY created_at ASC", (alert_id,))
    return [dict(r) for r in await cur.fetchall()]

# --- App ---

@asynccontextmanager
async def lifespan(app: FastAPI):
    async with aiosqlite.connect(DB_PATH) as db:
        await init_db(db)
        await correlation.init_corr_db(db)
        app.state.db = db
        yield

app = FastAPI(title="ProxyWatcher", lifespan=lifespan)

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    with open("frontend/index.html") as f:
        return f.read()

@app.post("/alerts")
async def receive_alert(features: dict[str, Any]):
    triage = await triage_with_claude(features)
    now = datetime.utcnow().isoformat()
    alert = {
        "created_at": now, "updated_at": now,
        "url": features.get("url", ""), "host": features.get("host", ""),
        "method": features.get("method", "GET"),
        "flags": json.dumps(features.get("flags", [])),
        "severity": triage.get("severity", "unknown"),
        "summary": triage.get("summary", ""),
        "recommended_action": triage.get("recommended_action", "investigate"),
        "raw": json.dumps(features),
        "status": "unassigned", "assigned_to": None,
        "closing_reason": None, "closed_at": None,
    }
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("""
            INSERT INTO alerts
            (created_at, updated_at, url, host, method, flags, severity, summary,
             recommended_action, raw, status, assigned_to, closing_reason, closed_at)
            VALUES
            (:created_at, :updated_at, :url, :host, :method, :flags, :severity, :summary,
             :recommended_action, :raw, :status, :assigned_to, :closing_reason, :closed_at)
        """, alert)
        await db.commit()
        alert["id"] = cursor.lastrowid
    await manager.broadcast("new_alert", alert)

    # Correlation pass — look for patterns across recent alerts from this host
    # (bursts, severity escalation, regular-interval beaconing). Failures here
    # must never break the alert pipeline.
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            events = await correlation.evaluate_host(db, alert["host"])
        for event, corr in events:
            await manager.broadcast(event, corr)
    except Exception as e:
        print(f"[proxywatcher] correlation error: {e}")

    return {"status": "ok", "id": alert["id"]}

@app.get("/alerts")
async def list_alerts(
    limit: int = 100, status: Optional[str] = None,
    severity: Optional[str] = None, host: Optional[str] = None,
    search: Optional[str] = None, assigned_to: Optional[str] = None,
):
    conditions, params = [], []
    if status:       conditions.append("status = ?");           params.append(status)
    if severity:     conditions.append("severity = ?");         params.append(severity)
    if host:         conditions.append("host LIKE ?");          params.append(f"%{host}%")
    if assigned_to:  conditions.append("assigned_to = ?");      params.append(assigned_to)
    if search:
        conditions.append("(url LIKE ? OR host LIKE ? OR summary LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(f"SELECT * FROM alerts {where} ORDER BY id DESC LIMIT ?", [*params, limit])
        rows = await cur.fetchall()
    return [dict(r) for r in rows]

@app.get("/alerts/{alert_id}")
async def get_alert(alert_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        row = await cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Alert not found")
        alert = dict(row)
        alert["notes"] = await get_notes(db, alert_id)
    return alert

@app.patch("/alerts/{alert_id}")
async def update_alert(alert_id: int, update: AlertUpdate):
    now = datetime.utcnow().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        if not await cur.fetchone():
            raise HTTPException(status_code=404, detail="Alert not found")
        fields = {"updated_at": now}
        if update.status is not None:
            fields["status"] = update.status
            if update.status == "closed":
                fields["closed_at"] = now
        if update.assigned_to is not None:   fields["assigned_to"] = update.assigned_to
        if update.closing_reason is not None: fields["closing_reason"] = update.closing_reason
        set_clause = ", ".join(f"{k} = ?" for k in fields)
        await db.execute(f"UPDATE alerts SET {set_clause} WHERE id = ?", [*fields.values(), alert_id])
        if update.note:
            await db.execute(
                "INSERT INTO alert_notes (alert_id, created_at, author, body) VALUES (?, ?, ?, ?)",
                (alert_id, now, "analyst", update.note))
        await db.commit()
        cur = await db.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        updated = dict(await cur.fetchone())
        updated["notes"] = await get_notes(db, alert_id)
    await manager.broadcast("alert_updated", updated)
    return updated

@app.post("/alerts/bulk")
async def bulk_update(update: BulkUpdate):
    now = datetime.utcnow().isoformat()
    fields = {"updated_at": now}
    if update.status:
        fields["status"] = update.status
        if update.status == "closed": fields["closed_at"] = now
    if update.assigned_to:   fields["assigned_to"] = update.assigned_to
    if update.closing_reason: fields["closing_reason"] = update.closing_reason
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    placeholders = ",".join("?" for _ in update.ids)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            f"UPDATE alerts SET {set_clause} WHERE id IN ({placeholders})",
            [*fields.values(), *update.ids])
        await db.commit()
    await manager.broadcast("bulk_updated", {"ids": update.ids, **fields})
    return {"status": "ok", "updated": len(update.ids)}

# --- Correlations ---

@app.get("/correlations")
async def list_correlations(status: Optional[str] = None, limit: int = 100):
    conditions, params = [], []
    if status:
        conditions.append("status = ?")
        params.append(status)
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            f"SELECT * FROM correlations {where} ORDER BY updated_at DESC LIMIT ?",
            [*params, limit])
        rows = [dict(r) for r in await cur.fetchall()]
    return rows

@app.get("/correlations/{corr_id}")
async def get_correlation(corr_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM correlations WHERE id = ?", (corr_id,))
        row = await cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Correlation not found")
        corr = dict(row)
        # Attach the contributing alerts so the UI can render them inline.
        ids = json.loads(corr["alert_ids"])
        alerts = []
        if ids:
            placeholders = ",".join("?" for _ in ids)
            cur = await db.execute(
                f"SELECT id, created_at, host, url, severity, flags, summary, status "
                f"FROM alerts WHERE id IN ({placeholders}) ORDER BY created_at ASC", ids)
            alerts = [dict(r) for r in await cur.fetchall()]
        corr["alerts"] = alerts
    return corr

@app.patch("/correlations/{corr_id}")
async def update_correlation(corr_id: int, update: CorrelationUpdate):
    now = datetime.utcnow().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM correlations WHERE id = ?", (corr_id,))
        if not await cur.fetchone():
            raise HTTPException(status_code=404, detail="Correlation not found")
        if update.status is not None:
            await db.execute(
                "UPDATE correlations SET status = ?, updated_at = ? WHERE id = ?",
                (update.status, now, corr_id))
            await db.commit()
        cur = await db.execute("SELECT * FROM correlations WHERE id = ?", (corr_id,))
        updated = dict(await cur.fetchone())
    await manager.broadcast("correlation_updated", updated)
    return updated

@app.get("/stats")
async def get_stats():
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity")
        by_severity = {r["severity"]: r["count"] for r in await cur.fetchall()}
        cur = await db.execute("SELECT status, COUNT(*) as count FROM alerts GROUP BY status")
        by_status = {r["status"]: r["count"] for r in await cur.fetchall()}
        cur = await db.execute("""
            SELECT strftime('%Y-%m-%dT%H:00:00', created_at) as hour, COUNT(*) as count
            FROM alerts WHERE created_at >= datetime('now', '-24 hours')
            GROUP BY hour ORDER BY hour ASC
        """)
        by_hour = [dict(r) for r in await cur.fetchall()]
        cur = await db.execute("""
            SELECT host, COUNT(*) as count FROM alerts
            GROUP BY host ORDER BY count DESC LIMIT 10
        """)
        top_hosts = [dict(r) for r in await cur.fetchall()]
        cur = await db.execute(
            "SELECT COUNT(*) as count FROM correlations WHERE status = 'open'")
        open_correlations = (await cur.fetchone())["count"]
    return {"by_severity": by_severity, "by_status": by_status,
            "by_hour": by_hour, "top_hosts": top_hosts,
            "open_correlations": open_correlations}

@app.get("/export")
async def export_alerts(format: str = "json"):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM alerts ORDER BY id DESC")
        rows = [dict(r) for r in await cur.fetchall()]
    if format == "csv":
        import csv, io
        buf = io.StringIO()
        if rows:
            writer = csv.DictWriter(buf, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        from fastapi.responses import Response
        return Response(content=buf.getvalue(), media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=proxywatcher-alerts.csv"})
    from fastapi.responses import Response
    return Response(content=json.dumps(rows, indent=2), media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=proxywatcher-alerts.json"})

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            await asyncio.sleep(30)
    except WebSocketDisconnect:
        manager.disconnect(ws)
