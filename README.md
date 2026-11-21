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

## The problem

CERT-In requires Indian organisations to keep security logs for **180 days** and to report specified incidents
within **6 hours**. Those logs are the only record of how a breach happened and what was taken, but they live
on the same machine the attacker now controls. With root access, the attacker deletes the incriminating lines
(MITRE ATT&CK **T1070, Indicator Removal**) and the company can no longer prove anything to an auditor, a
regulator or a court.

**Hashing the logs on the same server does not fix this.** An attacker with root edits an entry and
recomputes every hash after it. The file is again internally consistent and every local check passes.
The evidence has to leave the machine, and its fingerprint has to land somewhere nobody can rewrite.

## Why the blockchain is needed

Take the chain away and the design fails its own threat model. Whoever controls a server (the attacker, or
the company itself) can rewrite anything stored only on that server, including the witness database. The
RootRegistry contract on Quai provides the one thing a compromised machine cannot fake: **an independent,
public, write-once record of each fingerprint, made before the attack.** The contract has no function to edit
or delete an anchor, and anyone can read it without asking us.

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

* **System A (agent):** Linux or macOS, Python 3.10+. A **Windows** laptop works through **WSL (Ubuntu)**:
  clone and run everything inside the WSL terminal.
* **System B (witness):** Linux or macOS, Python 3.10+, Node.js 18+. This is the only machine that holds the
  Quai wallet key.
* Both laptops on the same network (a phone hotspot works well at venues)
* Optional: a third laptop or phone with a browser, used as the auditor's screen (`http://<B-ip>:8800`)

If System A runs in WSL, the witness URL is System B's LAN address as usual. WSL reaches the LAN through Windows,
so nothing else needs to be configured on the agent side.

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
It follows the system's light or dark setting. Use the sun/moon button in the top bar to switch, and the
browser remembers the choice.

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

## Real mode: real system logs, no synthetic data

By default `up-agent` generates synthetic log traffic, and `attack intrude` writes simulated attacker lines.
In **real mode** the agent watches the machine's real `/var/log/auth.log`. Every event comes from real
logins and real `sudo` commands, and the tampering is done as root on the real file.

**System A (Linux or WSL Ubuntu), once:**
```bash
sudo apt install -y rsyslog openssh-server
sudo service rsyslog start && sudo service ssh start
groups | grep -q adm || sudo usermod -aG adm $USER     # then log out/in (WSL: run `wsl --shutdown` in PowerShell)
./rd init-agent --real --witness http://<B-ip>:8800 --token <token>
./rd up-agent                                          # prints "REAL MODE"
```

**Create real security events:**
```bash
ssh nosuchuser@localhost          # type a wrong password 2-3 times → real "Failed password" lines (sshd)
./rd attack intrude               # real failed sudo attempts (a made-up wrong password is fed automatically)
```
`attack intrude` never asks for your real password. The wrong-password attempts are sent to `sudo`
non-interactively. The privileged step (a real `sudo cat /etc/shadow`) runs only from a root shell, where sudo
needs no password. On WSL, open one from PowerShell with `wsl -u root`, then `cd` into the project and run
`./rd attack intrude` again. On Linux, use `sudo -i` and do the same.

**Tamper as root, like a real attacker:**
```bash
sudo ./rd attack delete --match "/etc/shadow"                       # erase the evidence of reading the password hashes
sudo ./rd attack edit --match "nosuchuser" --replace "nosuchuser" "deploy"
sudo nano /var/log/auth.log                                         # or delete/edit any line by hand and save
```
The attack tools edit the file in place (same inode), so rsyslog keeps logging afterwards. The agent reads the
existing contents of `auth.log` on its first start, so those lines are witnessed from that moment on.

## Quai Network (Orchard testnet)

Anchoring runs on Quai through the official `quais` SDK. Out of the box `./rd up` uses a local EVM chain
(Hardhat), so the demo also works offline.

**Live deployment (Orchard, chain 15000, zone Cyprus-1):**

| | |
|---|---|
| RootRegistry contract | [`0x0066F967645A4B082E7411387Da6a0A59Fd33AA3`](https://orchard.quaiscan.io/address/0x0066F967645A4B082E7411387Da6a0A59Fd33AA3) |
| Test anchor (written and read back, root matched) | [`0x0040002c…501f08d`](https://orchard.quaiscan.io/tx/0x0040002cedf7c9e4f36791db508adff3c1b52131310b601591e56547e501f08d) |
| Cost of the deployment plus the first anchor | ≈ 0.0009 QUAI |
| Time for an anchor to confirm | ≈ 8–10 s |

**Set it up on System B (only there; System A never holds the key):**

1. **Get a funded Cyprus-1 key.** The address must start with `0x00`. Pelagus Wallet doesn't offer
   private-key export, so the simplest route is a **dedicated witness key**: create a fresh Cyprus-1 key on
   System B (for example with the `quais` SDK that `./rd setup` installs in `chain/node_modules`), write it
   straight into the config file without printing it, then send it a few test QUAI from Pelagus. 10 QUAI covers
   thousands of anchors. A dedicated key also means the witness never holds your main wallet.
2. In `config/witness.yaml` (gitignored; keep it `chmod 600`) set:
   ```yaml
   anchor_interval: 30
   chain:
     mode: quai
     quai:
       private_key: "0x…"      # testnet key only, never a key holding real funds
   ```
3. `./rd quai-info`: should show zone `0x00` (Cyprus-1) and a balance. It prints the address, never the key.
4. `./rd deploy --quai`: deploys RootRegistry and saves the address in the config.
5. `./rd up --reset`: anchors now go to Quai, and the dashboard links every transaction to
   `orchard.quaiscan.io`. Use `--reset` once, because batches anchored to the old local chain can't verify
   against the new contract.

Because a Quai anchor takes a few seconds to confirm, new lines in the live stream show **◷ witness** first and
turn **✓ on-chain** once their batch is confirmed.

Quai details that a plain Ethereum port gets wrong, all handled in `chain/quai.js`:
* Addresses carry a zone prefix, and the code checks that the wallet is inside a zone.
* Transactions must be signed with `quais`, not ethers.
* The RPC needs `usePathing`.
* Deployments must include the IPFS hash of the contract metadata. Root-Defense reads it from the CBOR
  trailer that solc already embeds in the bytecode, so no IPFS upload is needed.

## Reading what's on-chain: verify without trusting us

The chain stores **fingerprints, not logs**. Each anchor records `streamId` (which server), `root` (the
Merkle root of the batch), `firstSeq`–`lastSeq`, `count`, `reason` (0 scheduled, 1 critical, 2 alarm),
`timestamp` and `blockNumber`. The log text stays encrypted on the witness. To check a log, recompute its
fingerprint and compare it with the one on the chain.

| Who | How |
|---|---|
| Dashboard | **Auditor → Collect live logs & verify** reads every anchor back from the contract (`getAnchor`) and recomputes it. **Blockchain** lists every anchor with its explorer link. |
| Anyone with a browser | Open the contract on quaiscan: the logs tab shows each `Anchored` event, and **Read Contract** offers `getAnchor(i)` and `anchorCount()`. |
| An external auditor, offline | **Auditor → Download proof bundle**, then `./rd verify-bundle root-defense-proof-*.json`. It rebuilds each disputed line's Merkle proof and compares the result with the root it reads straight from the chain. |

Change a single character in a log line, or in the bundle, and the recomputed root no longer matches the one on
the chain.

## CERT-In compliance evidence

The **Compliance** tab tracks the 180-day retention requirement for each server. It also lists every critical
incident with a **6-hour reporting countdown** and the on-chain evidence for it. **Generate evidence report**
(`/api/v1/compliance/report`) produces a printable page for the regulator from the same anchored records.

## Commands

| Command | Where | What it does |
|---|---|---|
| `./rd setup` | both | install dependencies, compile the contract |
| `./rd init-witness` / `./rd up` | B | configure / start chain + witness + dashboard |
| `./rd init-agent [--real]` / `./rd up-agent` | A | configure / start the agent (demo traffic, or real `/var/log/auth.log`) |
| `[sudo] ./rd attack <intrude\|edit\|delete\|kill\|wipe\|truncate> [--match T] [--line N] [--replace OLD NEW]` | A | attacker actions |
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

## Performance

Measured with `./rd bench` (5,000 entries, one laptop, single process). Run it on your own hardware for current
numbers.

| Metric | Result |
|---|---|
| Agent sealing (hash chain + Ed25519 + key ratchet) | ≈ 6,000–12,000 entries/s |
| Witness ingestion (verify + encrypt + store) | ≈ 3,000–6,000 entries/s |
| Merkle root over 5,000 entries | ≈ 15 ms, inclusion proof 13 hashes |
| Edit/delete on System A → alarm on the dashboard | 0.2–0.9 s (measured end to end) |
| Agent killed → silence alarm | ≈ 8 s |
| Quai anchor confirmation | ≈ 8–10 s |

Each on-chain transaction commits to a whole batch, so the chain cost depends on the anchor interval, not on
log volume.

## Project layout

| Path | What it is |
|---|---|
| `rd` | Launcher (`./rd <command>`) |
| `scripts/setup.sh` | Creates the venv, installs dependencies, compiles the contract |
| `rootdefense/core/crypto.py` | Domain-separated hashes, Ed25519 key ratchet, RFC 6962 Merkle trees and proofs |
| `rootdefense/core/config.py` | Defaults and YAML config loading |
| `rootdefense/agent.py` | System A agent: watches files, seals entries, signed heartbeats, reports edits |
| `rootdefense/witness.py` | System B witness: verifies arrivals, silence monitor, Merkle batcher, anchoring |
| `rootdefense/store.py` | Witness storage (SQLite) with append-only triggers |
| `rootdefense/audit.py` | Auditor engine: history vs chain, live logs vs witness, proof bundles |
| `rootdefense/webapp.py` | HTTP API, dashboard, compliance report |
| `rootdefense/chain.py` | Local EVM (web3.py) and Quai (quais bridge) adapters |
| `rootdefense/demo.py` | Demo traffic generator and attacker actions (simulated and real mode) |
| `rootdefense/bench.py` | Benchmark |
| `chain/contracts/RootRegistry.sol` | The on-chain half: append-only anchors, no edit or delete function |
| `chain/quai.js` | Node bridge to Quai: info, deploy, anchor, read |
| `chain/compile.js` | solc build (London EVM) → `chain/build/RootRegistry.json` |
| `web/` | Dashboard (plain HTML/CSS/JS, no build step) |
| `tests/` | Unit, end-to-end and CLI tests (`.venv/bin/python -m pytest`, 11 passing) |

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
* Lines written since the last anchor are protected by the witness and the hash chain, but not yet by the
  blockchain. That window is the anchor interval (30 s on Quai), closed early by any critical event or alarm.
* The chain proves a line *existed and was changed*. Recovering the text of a deleted line relies on the
  witness's encrypted copy, and identifying *who* changed it needs host forensics.

## Prior art

Merkle-tree logging is well established: Certificate Transparency (RFC 6962), Trillian, Sigstore Rekor,
immudb. Root-Defense doesn't claim a new primitive. Its contribution is the combination built for the
incident-evidence workflow:
* an off-host witness that sees every line within a second;
* forward-secure signatures, so a stolen key can't rewrite the past;
* a silence alarm for a killed agent;
* write-once public anchoring on Quai;
* an auditor that names the exact changed line, with a proof that anyone can check against the chain;
* CERT-In retention and 6-hour reporting evidence.

---

*Track 02 · Problem B3 · The Big Hack 2.0*
