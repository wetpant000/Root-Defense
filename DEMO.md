# Demo runbook (3 minutes, real mode)

Roles: **Linux laptop = System B (witness, chain, dashboard)** · **Windows laptop (WSL Ubuntu) = System A (the server being attacked)**.
Everything shown comes from real system logs. No synthetic log lines are used.

## The day before
- [ ] `./rd setup` on both; on A also do the one-time real-mode setup in README ("Real mode")
- [ ] Same phone hotspot. From A: `curl http://<B-ip>:8800/api/v1/overview` returns JSON
- [ ] Do one full run of the script below; record a backup video
- [ ] (Quai) `./rd quai-info` shows a balance; `./rd deploy --quai` is done

## Right before going on stage
- B: `./rd up --reset`, then open `http://127.0.0.1:8800` full-screen and click once (enables the alarm sound)
- A: `sudo service rsyslog start; sudo service ssh start`, then `./rd reset --agent --yes && ./rd up-agent`
- A: open a second Ubuntu terminal for the attacker; run `sudo -v` once so sudo won't prompt mid-demo

## Script

| Time | Say | Do (on A unless noted) |
|---|---|---|
| 0:00 | "This laptop is a real Linux server. Its real auth log streams to a witness on another machine." | Point at ONLINE and the live stream on B |
| 0:20 | "Someone tries to break in." | `ssh nosuchuser@localhost`, then type 2 wrong passwords → real *Failed password* rows appear on B |
| 0:40 | "Now an insider with sudo reads the password hashes." | `./rd attack intrude` → real *COMMAND=… /etc/shadow* row, marked privileged, anchored at once |
| 1:00 | "With root they erase the evidence. Judge, pick a line." | `sudo ./rd attack delete --match "/etc/shadow"`, or `sudo nano /var/log/auth.log` → **red alarm in under a second** |
| 1:20 | "Which line, exactly?" | B: Auditor → **Collect live logs & verify** → TAMPERED, original line, ✓ verified Merkle proof |
| 1:45 | "Kill the agent." | `./rd attack kill` → **SILENT** alarm in about 8 s |
| 2:05 | "Wipe its database and keys." | `./rd attack wipe`; B: Auditor → *Verify witness vs blockchain* → still proven |
| 2:25 | "CERT-In: 180-day retention, 6-hour reporting clock." | B: Compliance → Generate evidence report |
| 2:45 | "Limit: the half second before a line leaves the host. Next: a 2-of-3 witness quorum." | Close |

## Numbers (from `./rd bench` and live runs)
- Tamper → alarm: about 0.2–0.7 s · agent silence → alarm: about 8 s
- Sealing about 12,700 entries/s · witness ingestion about 6,800 entries/s
- One anchor transaction per batch (every 15 s, plus instantly on critical events)
