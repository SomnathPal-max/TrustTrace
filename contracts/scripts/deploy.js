const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  console.log("Deploying ThreatRegistry smart contract to network:", hre.network.name);

  const [deployer] = await hre.ethers.getSigners();
  if (deployer) {
    console.log("Deployer address:", deployer.address);
    const balance = await hre.ethers.provider.getBalance(deployer.address);
    console.log("Account balance:", hre.ethers.formatEther(balance), "ETH");
  }

  const ThreatRegistry = await hre.ethers.getContractFactory("ThreatRegistry");
  const registry = await ThreatRegistry.deploy();
  await registry.waitForDeployment();

  const contractAddress = await registry.getAddress();
  const txHash = registry.deploymentTransaction()?.hash || "N/A";

  let explorerUrl = "";
  if (hre.network.name === "sepolia") {
    explorerUrl = `https://sepolia.etherscan.io/address/${contractAddress}`;
  } else if (hre.network.name === "amoy") {
    explorerUrl = `https://amoy.polygonscan.com/address/${contractAddress}`;
  } else {
    explorerUrl = `http://localhost:8545 (Local Node)`;
  }

  console.log("\n=======================================================");
  console.log("ThreatRegistry Deployed Successfully!");
  console.log("Contract Address:", contractAddress);
  console.log("Deployment Tx:", txHash);
  console.log("Network:", hre.network.name);
  console.log("Block Explorer:", explorerUrl);
  console.log("=======================================================\n");

  // Auto-update .env
  try {
    const envPath = path.resolve(__dirname, "../../.env");
    if (fs.existsSync(envPath)) {
      let content = fs.readFileSync(envPath, "utf-8");
      if (content.includes("CONTRACT_ADDRESS=")) {
        content = content.replace(/CONTRACT_ADDRESS=.*/g, `CONTRACT_ADDRESS=${contractAddress}`);
      } else {
        content += `\nCONTRACT_ADDRESS=${contractAddress}\n`;
      }
      fs.writeFileSync(envPath, content, "utf-8");
      console.log("Updated CONTRACT_ADDRESS in .env successfully!");
    }
  } catch (err) {
    console.warn("Could not auto-update .env:", err.message);
  }
}

main().catch((error) => {
  console.error("Deployment failed:", error);
  process.exitCode = 1;
});
