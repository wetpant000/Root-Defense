# Demo runbook (3 minutes)

## The day before
- [ ] `./rd setup` on both laptops; run the whole script below once
- [ ] Laptops on the same hotspot. On B: `hostname -I`; on A: `curl http://<B-ip>:8800/api/v1/overview`
- [ ] Record a backup video of a full run
- [ ] (Quai) `./rd quai-info` shows a balance; `./rd deploy --quai` is done

## Right before going on stage
- B: `./rd up --reset`, then open `http://<B-ip>:8800` full-screen; click once on the page to enable the alarm sound
- A: `./rd reset --agent --yes && ./rd up-agent`; open a second terminal for the attacks
- Wait about 30 s so the dashboard shows a healthy stream and a few anchors

## Script

| Time | Say | Do |
|---|---|---|
| 0:00 | "2 a.m. An attacker has root on a bank's server. First thing they do: erase their tracks." | Point at the green ONLINE card and the live stream |
| 0:20 | "Every line leaves the server in under a second, signed with a one-time key, and its Merkle root goes on-chain." | Blockchain tab → contract + batches; back to Live Monitor |
| 0:40 | "Here's the attacker." | A: `./rd attack intrude`, and orange *privileged* rows appear |
| 0:55 | "Now they cover their tracks. Judge, pick a line." | A: `./rd attack edit` (or `--line N`) → **red banner, detection time in seconds** |
| 1:20 | "Which lines, exactly? Ask the auditor." | Auditor → Collect live logs & verify → **TAMPERED**, original vs current, ✓ verified proofs |
| 1:45 | "Smarter attacker: kill the agent." | A: `./rd attack kill` → **SILENT** card + alarm in ~8 s |
| 2:05 | "Even smarter: wipe its database and keys." | A: `./rd attack wipe`; Auditor → *Verify witness vs blockchain* → still provable |
| 2:25 | "And for CERT-In: 180 days of retention and a 6-hour reporting clock." | Compliance tab → Generate evidence report |
| 2:45 | "Limit: the half second before a line leaves the host. Next step: a 2-of-3 witness quorum." | Close on the dashboard |

## Numbers to quote (measured with `./rd bench` on this laptop)
- Tamper detection: under 1 s from edit to alarm (shown live on the dashboard)
- Silence detection: about 8 s (5 s heartbeat + grace period)
- Agent sealing: about 12,700 entries/s · witness ingestion: about 6,800 entries/s
- Anchors per day: 5,760 at the 15 s demo interval; 144 at a 10-minute production interval. One transaction covers the whole batch.
