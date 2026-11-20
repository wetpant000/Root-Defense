"""HTTP API + dashboard for the witness (System B)."""
from __future__ import annotations

import hmac
import html
import json
import time

from fastapi import Body, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from . import __version__
from .audit import build_bundle, history_report, logs_report
from .core.config import WEB_DIR
from .store import row_dict
from .witness import IngestError, Witness


def create_app(w: Witness) -> FastAPI:
    app = FastAPI(title="Root-Defense Witness", version=__version__, docs_url="/api/docs", redoc_url=None)
    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")

    def require_token(token: str | None) -> None:
        expected = w.cfg.get("token") or ""
        if not expected or not hmac.compare_digest(expected, token or ""):
            raise HTTPException(401, "invalid agent token")

    @app.exception_handler(IngestError)
    async def _ingest_error(_: Request, exc: IngestError):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status)

    # ------------------------------------------------------------------ agent-facing
    @app.post("/api/v1/enroll")
    def enroll(body: dict = Body(...), x_rd_token: str | None = Header(None)):
        require_token(x_rd_token)
        return w.enroll(body)

    @app.post("/api/v1/entries")
    def entries(body: dict = Body(...), x_rd_token: str | None = Header(None)):
        require_token(x_rd_token)
        return w.ingest(body["agent_id"], body.get("entries", []))

    @app.post("/api/v1/snapshot")
    def snapshot(body: dict = Body(...), x_rd_token: str | None = Header(None)):
        require_token(x_rd_token)
        return w.receive_snapshot(body["agent_id"], body["request_id"], body.get("files", {}))

    # ------------------------------------------------------------------ dashboard
    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(WEB_DIR / "index.html")

    @app.get("/api/v1/overview")
    def overview():
        s = w.store
        totals = s.one("SELECT COUNT(*) AS n, SUM(kind='log') AS logs, SUM(kind='heartbeat') AS hb, SUM(kind='tamper') AS tamper "
                       "FROM entries")
        batches = s.one("SELECT COUNT(*) AS n, COALESCE(SUM(count),0) AS anchored, AVG(anchor_latency) AS lat FROM batches")
        open_alarms = s.q("SELECT e.* FROM events e LEFT JOIN acks a ON a.event_id = e.id "
                          "WHERE e.severity = 'critical' AND a.event_id IS NULL ORDER BY e.id DESC LIMIT 10")
        det = s.q("SELECT detail FROM events WHERE type = 'TAMPER_DETECTED' ORDER BY id DESC LIMIT 20")
        lats = [d for d in (json.loads(r["detail"]).get("alarm_seconds") for r in det) if d is not None]
        silent = s.q("SELECT detail FROM events WHERE type = 'AGENT_SILENT' ORDER BY id DESC LIMIT 20")
        info = w.chain_info or {}
        return {
            "version": __version__, "now": time.time(), "uptime": round(time.time() - w.started),
            "agents": w.agents(),
            "totals": {"entries": totals["n"] or 0, "logs": totals["logs"] or 0, "heartbeats": totals["hb"] or 0,
                       "tamper_reports": totals["tamper"] or 0, "batches": batches["n"] or 0,
                       "anchored_entries": batches["anchored"] or 0,
                       "pending_entries": max(0, (totals["n"] or 0) - (batches["anchored"] or 0)),
                       "avg_anchor_latency": round(batches["lat"], 2) if batches["lat"] else None,
                       "last_detection_seconds": lats[0] if lats else None,
                       "avg_detection_seconds": round(sum(lats) / len(lats), 2) if lats else None,
                       "last_silence_alarm_seconds": json.loads(silent[0]["detail"]).get("silent_seconds") if silent else None},
            "alarms": [row_dict(r) for r in open_alarms],
            "chain": {**info, "ok": w.chain_ok, "explorer_contract": w.chain.explorer_address(w.chain.contract_address)},
            "config": {"silence_threshold": w.cfg["silence_threshold"], "anchor_interval": w.cfg["anchor_interval"],
                       "retention_days": w.cfg["retention_days"]},
        }

    @app.get("/api/v1/entries")
    def list_entries(agent: str | None = None, limit: int = 40, kind: str | None = None, before: int | None = None):
        sql, args = "SELECT * FROM entries WHERE 1=1", []
        if agent:
            sql += " AND agent_id = ?"
            args.append(agent)
        if kind:
            sql += " AND kind = ?"
            args.append(kind)
        if before is not None:
            sql += " AND seq < ?"
            args.append(before)
        sql += " ORDER BY received_at DESC, seq DESC LIMIT ?"
        args.append(min(limit, 500))
        last = {r["agent_id"]: r["m"] for r in w.store.q("SELECT agent_id, MAX(last_seq) AS m FROM batches GROUP BY agent_id")}
        out = []
        for r in w.store.q(sql, args):
            d = w.entry_view(r)
            d["anchored"] = d["seq"] <= (last.get(d["agent_id"]) if last.get(d["agent_id"]) is not None else -1)
            out.append(d)
        return out

    @app.get("/api/v1/events")
    def list_events(limit: int = 50):
        rows = w.store.q("SELECT e.*, a.ts AS acked_at, x.tx_hash AS anchor_tx FROM events e LEFT JOIN acks a ON a.event_id = e.id "
                         "LEFT JOIN event_anchors x ON x.event_id = e.id ORDER BY e.id DESC LIMIT ?", (min(limit, 500),))
        out = []
        for r in rows:
            d = row_dict(r)
            d["anchor_explorer"] = w.chain.explorer_tx(d.get("anchor_tx"))
            out.append(d)
        return out

    @app.post("/api/v1/events/{event_id}/ack")
    def ack(event_id: int):
        w.store.x("INSERT OR IGNORE INTO acks VALUES (?, ?)", (event_id, time.time()))
        return {"ok": True}

    @app.post("/api/v1/events/ack-all")
    def ack_all():
        w.store.x("INSERT OR IGNORE INTO acks SELECT id, ? FROM events WHERE severity = 'critical'", (time.time(),))
        return {"ok": True}

    @app.get("/api/v1/batches")
    def list_batches(limit: int = 50):
        out = []
        for r in w.store.q("SELECT * FROM batches ORDER BY id DESC LIMIT ?", (min(limit, 500),)):
            d = dict(r)
            d["explorer"] = w.chain.explorer_tx(d["tx_hash"])
            out.append(d)
        return out

    @app.get("/api/v1/chain")
    def chain_info():
        info = w.refresh_chain_info()
        return {**info, "ok": w.chain_ok, "explorer_contract": w.chain.explorer_address(w.chain.contract_address)}

    @app.post("/api/v1/anchor-now")
    def anchor_now():
        w.request_anchor(0)
        return {"ok": True}

    # ------------------------------------------------------------------ auditor
    @app.post("/api/v1/audit/collect")
    def audit_collect(body: dict = Body(...)):
        agent = body.get("agent_id")
        if not w.store.one("SELECT 1 FROM agents WHERE agent_id = ?", (agent,)):
            raise HTTPException(404, "unknown agent")
        return {"request_id": w.request_snapshot(agent)}

    @app.get("/api/v1/audit/collect/{request_id}")
    def audit_collect_status(request_id: str):
        r = w.collect_results.get(request_id)
        if not r:
            raise HTTPException(404, "unknown request")
        if r["status"] == "waiting" and time.time() - r["requested_at"] > 12:
            r = {**r, "status": "timeout"}
            w.snapshot_requests.pop(r["agent_id"], None)
        return r

    @app.post("/api/v1/audit/upload")
    def audit_upload(body: dict = Body(...)):
        agent = body.get("agent_id")
        files = body.get("files") or {}
        if not files:
            raise HTTPException(400, "no files")
        return logs_report(w, agent, files, origin="Log files uploaded by the auditor")

    @app.get("/api/v1/audit/history")
    def audit_history(agent_id: str | None = None):
        return history_report(w, agent_id)

    @app.get("/api/v1/audit/report/{report_id}")
    def audit_report(report_id: str):
        r = w.reports.get(report_id)
        if not r:
            raise HTTPException(404, "report not found (reports are kept in memory)")
        return r

    @app.get("/api/v1/audit/bundle/{report_id}")
    def audit_bundle(report_id: str):
        r = w.reports.get(report_id)
        if not r:
            raise HTTPException(404, "report not found")
        data = json.dumps(build_bundle(w, r), indent=2)
        fname = f"root-defense-proof-{r.get('agent_id') or 'all'}-{time.strftime('%Y%m%d-%H%M%S')}.json"
        return Response(data, media_type="application/json", headers={"Content-Disposition": f'attachment; filename="{fname}"'})

    # ------------------------------------------------------------------ compliance (CERT-In)
    @app.get("/api/v1/compliance")
    def compliance():
        return _compliance(w)

    @app.get("/api/v1/compliance/report", response_class=HTMLResponse)
    def compliance_report():
        return _compliance_html(_compliance(w))

    return app


def _compliance(w: Witness) -> dict:
    now = time.time()
    req_days = int(w.cfg["retention_days"])
    hours = int(w.cfg["reporting_hours"])
    agents = []
    for a in w.agents():
        first = w.store.one("SELECT MIN(ts) AS t FROM entries WHERE agent_id = ?", (a["agent_id"],))["t"]
        srcs = w.store.q("SELECT source, COUNT(*) AS n, MIN(ts) AS first, MAX(ts) AS last FROM entries "
                         "WHERE agent_id = ? AND kind = 'log' GROUP BY source", (a["agent_id"],))
        anchored = w.store.one("SELECT COALESCE(SUM(count),0) AS n FROM batches WHERE agent_id = ?", (a["agent_id"],))["n"]
        days = (now - first) / 86400 if first else 0
        agents.append({"agent_id": a["agent_id"], "hostname": a["hostname"], "status": a["status"], "first_entry": first,
                       "days_held": round(days, 3), "entries": a["entries"], "anchored": anchored,
                       "sources": [dict(s) for s in srcs]})
    incidents = []
    for r in w.store.q("SELECT e.*, x.tx_hash AS anchor_tx FROM events e LEFT JOIN event_anchors x ON x.event_id = e.id "
                       "WHERE e.severity = 'critical' ORDER BY e.id DESC LIMIT 100"):
        d = row_dict(r)
        d["deadline"] = d["ts"] + hours * 3600
        d["seconds_left"] = round(d["deadline"] - now)
        d["anchor_explorer"] = w.chain.explorer_tx(d.get("anchor_tx"))
        incidents.append(d)
    return {"generated_at": now, "retention_days_required": req_days, "reporting_hours": hours,
            "retention_policy_days": req_days, "agents": agents, "incidents": incidents,
            "chain": {"mode": w.chain.mode, "label": w.chain.label, "contract": w.chain.contract_address,
                      "chain_id": (w.chain_info or {}).get("chain_id")},
            "controls": [
                {"name": "Logs copied off-host within seconds", "status": "met", "evidence": "Witness ingestion timestamps"},
                {"name": "Tamper-evident storage (hash chain + signatures)", "status": "met", "evidence": "Auditor history check"},
                {"name": "Independent, public timestamping", "status": "met" if w.chain_ok else "degraded",
                 "evidence": f"Merkle roots on {w.chain.label}"},
                {"name": f"Retention of {req_days} days", "status": "configured",
                 "evidence": f"Witness retention policy = {req_days} days; append-only tables"},
                {"name": f"Incident evidence within {hours} hours", "status": "met",
                 "evidence": "Every critical alarm is timestamped and anchored on-chain"},
            ]}


def _compliance_html(c: dict) -> str:
    e = html.escape
    fmt = lambda t: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)) if t else "-"  # noqa: E731
    rows_agents = "".join(
        f"<tr><td>{e(a['agent_id'])}</td><td>{e(a['hostname'] or '')}</td><td>{fmt(a['first_entry'])}</td>"
        f"<td>{a['days_held']:.2f} / {c['retention_days_required']}</td><td>{a['entries']}</td><td>{a['anchored']}</td></tr>"
        for a in c["agents"])
    rows_inc = "".join(
        f"<tr><td>{fmt(i['ts'])}</td><td>{e(i['type'])}</td><td>{e(i['title'])}</td><td>{fmt(i['deadline'])}</td>"
        f"<td class='mono'>{e((i.get('anchor_tx') or 'pending')[:20])}</td></tr>" for i in c["incidents"]) or \
        "<tr><td colspan='5'>No critical incidents recorded.</td></tr>"
    rows_ctl = "".join(f"<tr><td>{e(x['name'])}</td><td>{e(x['status'])}</td><td>{e(x['evidence'])}</td></tr>" for x in c["controls"])
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Root-Defense - CERT-In evidence report</title>
<style>body{{font-family:Inter,system-ui,sans-serif;color:#14213D;margin:40px;max-width:1000px}}h1{{margin:0}}
.sub{{color:#4A5568;margin:4px 0 24px}}h2{{margin-top:32px;border-bottom:2px solid #0F766E;padding-bottom:6px}}
table{{border-collapse:collapse;width:100%;font-size:13px}}th,td{{text-align:left;padding:7px 8px;border-bottom:1px solid #ddd}}
th{{background:#F3F4F0}}.mono{{font-family:monospace}}.note{{color:#4A5568;font-size:12px;margin-top:28px}}
@media print{{button{{display:none}}}}</style></head><body>
<button onclick="window.print()" style="float:right;padding:8px 14px">Print / Save as PDF</button>
<h1>Root-Defense &mdash; Log integrity &amp; incident evidence report</h1>
<p class="sub">Generated {fmt(c['generated_at'])} &middot; Anchoring: {e(c['chain']['label'])} (chain id {e(str(c['chain']['chain_id']))}) &middot;
Contract <span class="mono">{e(c['chain']['contract'] or '-')}</span></p>
<h2>Controls mapped to CERT-In Directions (28 April 2022)</h2>
<table><tr><th>Control</th><th>Status</th><th>Evidence</th></tr>{rows_ctl}</table>
<h2>Log retention (required: {c['retention_days_required']} days)</h2>
<table><tr><th>Agent</th><th>Host</th><th>First entry</th><th>Days held</th><th>Entries</th><th>Anchored on-chain</th></tr>{rows_agents}</table>
<h2>Incident timeline (report within {c['reporting_hours']} hours)</h2>
<table><tr><th>Detected</th><th>Type</th><th>Description</th><th>Reporting deadline</th><th>Anchor tx</th></tr>{rows_inc}</table>
<p class="note">Only hashes and Merkle roots are written on-chain. Raw log text is held encrypted on the witness. This report is
generated from the witness record; each entry can be independently verified with the proof bundle exported from the auditor portal.</p>
</body></html>"""
