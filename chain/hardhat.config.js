// Local demo chain for Root-Defense (stand-in for Quai Orchard when no test QUAI is available).
// Run with: npm run node   (listens on 127.0.0.1:8545, chain id 31337)
module.exports = {
  solidity: "0.8.24",
  networks: {
    hardhat: {
      chainId: 31337,
      mining: { auto: true },
    },
  },
};
