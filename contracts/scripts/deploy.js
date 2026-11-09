const hre = require("hardhat");

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
  console.log("\n=======================================================");
  console.log("ThreatRegistry deployed successfully!");
  console.log("Contract Address:", contractAddress);
  console.log("Network:", hre.network.name);
  console.log("=======================================================\n");
  console.log("To configure backend and frontend with this contract, set:");
  console.log(`WEB3_CONTRACT_ADDRESS=${contractAddress}`);
  console.log(`NEXT_PUBLIC_CONTRACT_ADDRESS=${contractAddress}`);
}

main().catch((error) => {
  console.error("Deployment failed:", error);
  process.exitCode = 1;
});
