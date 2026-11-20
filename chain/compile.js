// Compiles contracts/RootRegistry.sol with solc-js into build/RootRegistry.json (abi + bytecode).
// evmVersion is pinned to "london" so the bytecode runs on both Hardhat and Quai's EVM.
const fs = require("fs");
const path = require("path");
const solc = require("solc");

const src = fs.readFileSync(path.join(__dirname, "contracts", "RootRegistry.sol"), "utf8");
const input = {
  language: "Solidity",
  sources: { "RootRegistry.sol": { content: src } },
  settings: {
    optimizer: { enabled: true, runs: 200 },
    evmVersion: "london",
    outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } },
  },
};

const out = JSON.parse(solc.compile(JSON.stringify(input)));
const errors = (out.errors || []).filter((e) => e.severity === "error");
for (const e of out.errors || []) console.error(e.formattedMessage);
if (errors.length) process.exit(1);

const c = out.contracts["RootRegistry.sol"].RootRegistry;
fs.mkdirSync(path.join(__dirname, "build"), { recursive: true });
const artifact = {
  contractName: "RootRegistry",
  compiler: `solc ${solc.version()}`,
  evmVersion: "london",
  abi: c.abi,
  bytecode: "0x" + c.evm.bytecode.object,
};
fs.writeFileSync(path.join(__dirname, "build", "RootRegistry.json"), JSON.stringify(artifact, null, 2));
console.log(`Compiled RootRegistry (${artifact.compiler}) -> build/RootRegistry.json`);
