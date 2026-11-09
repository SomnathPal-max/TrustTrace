const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("ThreatRegistry", function () {
  let ThreatRegistry, registry, owner, user1, user2;

  beforeEach(async function () {
    [owner, user1, user2] = await ethers.getSigners();
    ThreatRegistry = await ethers.getContractFactory("ThreatRegistry");
    registry = await ThreatRegistry.deploy();
    await registry.waitForDeployment();
  });

  it("should commit a new report with revision 1 and status Reported", async function () {
    const reportId = ethers.keccak256(ethers.toUtf8Bytes("report-uuid-12345"));
    const reportHash = ethers.keccak256(ethers.toUtf8Bytes("canonical-json-content-hash"));

    await expect(registry.connect(user1).commitReport(reportId, reportHash))
      .to.emit(registry, "ReportCommitted")
      .withArgs(reportId, reportHash, user1.address, 1, (await ethers.provider.getBlock("latest")).timestamp + 1);

    const record = await registry.getReport(reportId);
    expect(record.reportHash).to.equal(reportHash);
    expect(record.reporter).to.equal(user1.address);
    expect(record.status).to.equal(0); // Status.Reported
    expect(record.revision).to.equal(1);
    expect(await registry.reportExists(reportId)).to.be.true;
  });

  it("should reject report revision from a different address", async function () {
    const reportId = ethers.keccak256(ethers.toUtf8Bytes("report-uuid-12345"));
    const reportHash1 = ethers.keccak256(ethers.toUtf8Bytes("hash-v1"));
    const reportHash2 = ethers.keccak256(ethers.toUtf8Bytes("hash-v2"));

    await registry.connect(user1).commitReport(reportId, reportHash1);

    await expect(
      registry.connect(user2).commitReport(reportId, reportHash2)
    ).to.be.revertedWith("Only original reporter can revise report");
  });

  it("should increment revision when original reporter revises", async function () {
    const reportId = ethers.keccak256(ethers.toUtf8Bytes("report-uuid-12345"));
    const reportHash1 = ethers.keccak256(ethers.toUtf8Bytes("hash-v1"));
    const reportHash2 = ethers.keccak256(ethers.toUtf8Bytes("hash-v2"));

    await registry.connect(user1).commitReport(reportId, reportHash1);
    await registry.connect(user1).commitReport(reportId, reportHash2);

    const record = await registry.getReport(reportId);
    expect(record.reportHash).to.equal(reportHash2);
    expect(record.revision).to.equal(2);
  });

  it("should allow a third party to update status, but forbid the reporter from validating own report", async function () {
    const reportId = ethers.keccak256(ethers.toUtf8Bytes("report-uuid-12345"));
    const reportHash = ethers.keccak256(ethers.toUtf8Bytes("hash-v1"));

    await registry.connect(user1).commitReport(reportId, reportHash);

    // Reporter cannot update own status
    await expect(
      registry.connect(user1).updateStatus(reportId, 1) // Verified
    ).to.be.revertedWith("Reporter cannot validate their own report");

    // Third party can update status
    await expect(registry.connect(user2).updateStatus(reportId, 1))
      .to.emit(registry, "StatusUpdated");

    const record = await registry.getReport(reportId);
    expect(record.status).to.equal(1); // Verified
  });

  it("should reject zero hashes", async function () {
    const reportId = ethers.keccak256(ethers.toUtf8Bytes("report-uuid-zero"));
    const zeroBytes = ethers.ZeroHash;

    await expect(
      registry.connect(user1).commitReport(reportId, zeroBytes)
    ).to.be.revertedWith("Zero report hash rejected");
  });
});
