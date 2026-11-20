#!/usr/bin/env node
// Root-Defense <-> Quai Network bridge (uses the official quais SDK).
// Called by the Python batcher. Reads one JSON request on stdin, writes one JSON reply on stdout.
//
// Requests:
//   {"cmd":"info",   "rpc":..., "privateKey"?:...}
//   {"cmd":"deploy", "rpc":..., "privateKey":...}
//   {"cmd":"anchor", "rpc":..., "privateKey":..., "contract":..., "streamId":"0x..", "root":"0x..",
//                    "firstSeq":n, "lastSeq":n, "count":n, "reason":n}
//   {"cmd":"get",    "rpc":..., "contract":..., "index":n}
//   {"cmd":"count",  "rpc":..., "contract":...}
const fs = require("fs");
const path = require("path");
const quais = require("quais");

const artifact = JSON.parse(fs.readFileSync(path.join(__dirname, "build", "RootRegistry.json"), "utf8"));

function reply(obj) {
  process.stdout.write(JSON.stringify(obj) + "\n");
}

function provider(rpc) {
  return new quais.JsonRpcProvider(rpc, undefined, { usePathing: true });
}

function wallet(req) {
  if (!req.privateKey) throw new Error("privateKey is required for this command");
  const w = new quais.Wallet(req.privateKey, provider(req.rpc));
  const zone = quais.getZoneForAddress(w.address);
  if (!zone) {
    throw new Error(
      `Address ${w.address} is not inside any Quai zone. Export the private key of a Cyprus-1 address from Pelagus Wallet.`
    );
  }
  return w;
}

async function main() {
  const req = JSON.parse(fs.readFileSync(0, "utf8"));
  const p = provider(req.rpc);

  switch (req.cmd) {
    case "info": {
      const out = { chainId: (await p.getNetwork()).chainId.toString(), block: await p.getBlockNumber(quais.Shard.Cyprus1) };
      if (req.privateKey) {
        const w = wallet(req);
        out.address = w.address;
        out.zone = quais.getZoneForAddress(w.address);
        out.balance = quais.formatQuai(await p.getBalance(w.address));
      }
      return reply({ ok: true, ...out });
    }
    case "deploy": {
      const w = wallet(req);
      const factory = new quais.ContractFactory(artifact.abi, artifact.bytecode, w);
      const c = await factory.deploy();
      await c.waitForDeployment();
      const tx = c.deploymentTransaction();
      return reply({ ok: true, address: await c.getAddress(), txHash: tx ? tx.hash : null });
    }
    case "anchor": {
      const w = wallet(req);
      const c = new quais.Contract(req.contract, artifact.abi, w);
      const tx = await c.anchor(req.streamId, req.root, req.firstSeq, req.lastSeq, req.count, req.reason);
      const rc = await tx.wait();
      let index = null;
      for (const log of rc.logs || []) {
        try {
          const parsed = c.interface.parseLog(log);
          if (parsed && parsed.name === "Anchored") index = Number(parsed.args.index);
        } catch (_) {}
      }
      return reply({ ok: true, txHash: tx.hash, blockNumber: Number(rc.blockNumber), index });
    }
    case "get": {
      const c = new quais.Contract(req.contract, artifact.abi, p);
      const a = await c.getAnchor(req.index);
      return reply({
        ok: true,
        anchor: {
          streamId: a.streamId, root: a.root, firstSeq: Number(a.firstSeq), lastSeq: Number(a.lastSeq),
          count: Number(a.count), reason: Number(a.reason), timestamp: Number(a.timestamp), blockNumber: Number(a.blockNumber),
        },
      });
    }
    case "getMany": {
      const c = new quais.Contract(req.contract, artifact.abi, p);
      const anchors = {};
      for (const i of req.indices || []) {
        const a = await c.getAnchor(i);
        anchors[i] = {
          streamId: a.streamId, root: a.root, firstSeq: Number(a.firstSeq), lastSeq: Number(a.lastSeq),
          count: Number(a.count), reason: Number(a.reason), timestamp: Number(a.timestamp), blockNumber: Number(a.blockNumber),
        };
      }
      return reply({ ok: true, anchors });
    }
    case "count": {
      const c = new quais.Contract(req.contract, artifact.abi, p);
      return reply({ ok: true, count: Number(await c.anchorCount()) });
    }
    default:
      throw new Error(`unknown cmd ${req.cmd}`);
  }
}

main()
  .then(() => process.exit(0))
  .catch((e) => {
    reply({ ok: false, error: e.shortMessage || e.message || String(e) });
    process.exit(1);
  });
