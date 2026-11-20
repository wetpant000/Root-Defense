# Root-Defense

**Tamper-evident security logs that an attacker with root access can't quietly erase.**
The Big Hack 2.0 · Track 02 · Problem B3

Root-Defense copies every log line off the server within about a second, notices immediately when the logging
agent goes silent, and writes Merkle roots of the log history to a smart contract on Quai Network.
Nobody can rewrite those roots, including the company itself. An auditor portal then shows **GENUINE** or
**TAMPERED** and highlights the exact line that changed, with a proof that anyone can check against the
blockchain.

```
 System A - monitored server (attacker may get root)        System B - witness (separate machine)
 ┌──────────────────────────────────────────────┐          ┌───────────────────────────────────────────────┐
 │ auth.log, app.log ──► Agent                  │  HTTP    │  Witness (append-only, encrypted at rest)     │
 │   • SHA-256 hash chain                       │  (LAN)   │   • verifies chain + signatures on arrival    │
 │   • Ed25519 forward-secure key ratchet       │ ───────► │   • silence alarm (no heartbeat for 8 s)      │
 │   • signed heartbeat every 5 s               │ < 1 s    │  Merkle batcher ──► RootRegistry contract     │
 │   • re-checks sent lines, reports edits      │          │   (every 15 s + instantly on critical events) │
 └──────────────────────────────────────────────┘          │  Dashboard + Auditor portal + CERT-In report  │
                                                           └───────────────────────────────────────────────┘
```

## What it catches

| Attack | Result | How |
|---|---|---|
| Edit or delete a log line | **Caught in < 1 s**, exact line located | Agent re-checks sent lines; auditor diffs against the witnessed record |
| Insert fake lines | Caught | Lines never witnessed are flagged |
| Kill the agent / cut the network | **Alarm in ~8 s** | Signed heartbeats stop; the gap is recorded and anchored |
| Wipe the agent's local database | Caught; proof still works | Witness + chain hold the history; re-enrollment raises an alarm |
| Steal the signing key, re-sign history | Rejected | Key ratchet: every past private key is already deleted |
| Root on the witness rewrites its DB | Caught | Auditor recomputes every root and compares with the contract |
| Change a line in the first ~0.5 s, before it's sent | **Not prevented** | The window is under a second, not zero |

Only hashes and Merkle roots go on-chain. Raw log text never does.

## Requirements

* **System A (agent):** Linux or macOS, Python 3.10+
* **System B (witness):** Linux or macOS, Python 3.10+, Node.js 18+
* Both laptops on the same network (a phone hotspot works well at venues)

## Setup (once, on both laptops)

```bash
git clone <this repo> root-defense && cd root-defense     # or copy the folder
./rd setup
```

## Run the two-system demo

**System B (witness):**
```bash
./rd init-witness          # prints the exact command to run on System A, including a token
./rd up                    # local chain + contract + witness + dashboard at http://<B-ip>:8800
```
If a firewall is on: `sudo ufw allow 8800/tcp`.

**System A (monitored server):**
```bash
./rd init-agent --witness http://<B-ip>:8800 --token <token printed on B>
./rd up-agent              # realistic log traffic + the Root-Defense agent
```

Open the dashboard on System B (or on any laptop on the network): `http://<B-ip>:8800`

### Attack script (run on System A, in a second terminal)

```bash
./rd attack intrude        # attacker logs in as root, reads /etc/shadow, adds a backdoor user, copies data out
./rd attack edit           # attacker rewrites their IP in auth.log  → red alarm on the dashboard in < 1 s
./rd attack delete         # attacker deletes the lines              → alarm again
./rd attack kill           # SIGKILL the agent                       → "agent silent" alarm in ~8 s
./rd attack wipe           # delete the agent's local DB and keys    → proof still verifies
./rd up-agent              # restart: the agent re-enrolls with a new key, and that is itself an alarm
```
You can also do it by hand: edit `data/demo-logs/auth.log` with any editor, or let a judge pick a line:
`./rd attack edit --line 12 --text "anything"`.

Then, in the dashboard: **Auditor → Collect live logs & verify** → TAMPERED, with the exact lines, the witnessed
original and a verified Merkle proof for each. **Download proof bundle**, then verify it independently:

```bash
./rd verify-bundle root-defense-proof-*.json
```

Start a clean demo at any time: `./rd up --reset` on B and `./rd reset --agent --yes` on A.

## Switching to Quai Network (Orchard testnet)

The contract and the code already support Quai through the official `quais` SDK. The demo runs on a local
EVM chain only because the public faucet was unavailable. To switch:

1. In Pelagus Wallet, create a **Cyprus-1** address, get test QUAI (Quai Discord), and export its private key.
2. In `config/witness.yaml` set:
   ```yaml
   anchor_interval: 30
   chain:
     mode: quai
     quai:
       private_key: "0x…"      # testnet key only, never a key holding real funds
   ```
3. `./rd quai-info`: should show `zone: cyprus1` and a balance.
4. `./rd deploy --quai`: deploys RootRegistry and saves the address.
5. `./rd up`: anchors now go to Quai. The dashboard links every transaction to `orchard.quaiscan.io`.

## Commands

| Command | Where | What it does |
|---|---|---|
| `./rd setup` | both | install dependencies, compile the contract |
| `./rd init-witness` / `./rd up` | B | configure / start chain + witness + dashboard |
| `./rd init-agent` / `./rd up-agent` | A | configure / start agent with demo traffic |
| `./rd attack <intrude\|edit\|delete\|kill\|wipe\|truncate>` | A | simulate the attacker |
| `./rd status` | B | witness status in the terminal |
| `./rd verify-bundle FILE` | any | independently verify a proof bundle against the chain |
| `./rd bench` | any | throughput numbers for the Evidence slide |
| `./rd quai-info` / `./rd deploy --quai` | B | Quai Orchard checks / deployment |
| `./rd reset --witness/--agent` | B/A | clear demo data |

## How it works

* **Entry:** `hash = sha256("RD-ENTRY-v1" ‖ canonical_json(agent_id, seq, ts, kind, source, line_no, line_hash, prev_hash, next_pk, meta))`.
  `prev_hash` chains every entry to the one before it.
* **Forward-secure signatures:** each entry is signed with a one-time Ed25519 key and carries the public key of
  the next one. The old private key is discarded right after signing, and the entry, key and chain head are
  committed atomically. The witness follows the chain of public keys from the key registered at enrollment.
* **Witness:** verifies sequence, link, hash and signature on arrival, and rejects anything else (forks and
  forgeries raise alarms). SQLite triggers make every evidence table append-only. Log text is encrypted with Fernet.
* **Merkle anchoring:** RFC 6962 tree (`leaf = H(0x00‖h)`, `node = H(0x01‖l‖r)`). Each batch root goes to
  `RootRegistry.anchor(streamId, root, firstSeq, lastSeq, count, reason)` every 15 s, and immediately
  on privileged activity or any alarm. Alarms themselves are anchored too.
* **Auditor:** recomputes everything, compares each root with the contract, and diffs the current files against
  the witnessed lines (pairing edited lines by similarity). Every finding carries an inclusion proof.

## Project layout

```
rd                      launcher
rootdefense/core/       crypto (hash chain, ratchet, Merkle) and config
rootdefense/agent.py    System A agent
rootdefense/witness.py  System B witness, silence monitor, Merkle batcher
rootdefense/audit.py    auditor engine and proof bundles
rootdefense/webapp.py   HTTP API, compliance report
rootdefense/chain.py    local EVM (web3.py) and Quai (quais) adapters
chain/                  RootRegistry.sol, compiler, Hardhat config, quai.js bridge
web/                    dashboard
tests/                  unit and end-to-end tests  (.venv/bin/python -m pytest)
```

## Honest limits

* An attacker who already has root can alter a line in the ~0.5 s before the agent reads it.
* If the attacker controls both the host and the witness, roots already on-chain still protect older history.
  A 2-of-3 witness quorum is the next step.
* A live attacker can write false entries in real time. Root-Defense proves logs weren't changed *afterwards*.
* The agent token authenticates enrollment. Someone with root on A can read it and re-enroll, but every
  re-enrollment is recorded as a critical, anchored alarm.
* Log rotation currently looks like truncation and is reported as tampering; rotation-aware handling is future work.
* Agent-to-witness traffic is plain HTTP on the LAN for the demo. Put TLS (e.g. a reverse proxy) in front of the
  witness for a real deployment.
