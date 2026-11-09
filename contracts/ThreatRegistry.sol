// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ThreatRegistry
 * @dev Cryptographic commitment registry for Link & Scam Detective (HackMatrix 2026).
 * Strictly preserves privacy: stores ONLY hashes, timestamps, addresses, and status codes.
 * Zero string, PII, or raw URL storage (HC-07 & HC-08).
 */
contract ThreatRegistry {
    enum Status {
        Reported,
        Verified,
        Disputed
    }

    struct ReportRecord {
        bytes32 reportHash;
        uint256 timestamp;
        address reporter;
        Status status;
        uint256 revision;
    }

    // Mapping from reportIdentifier (SHA-256 of report UUID) to ReportRecord
    mapping(bytes32 => ReportRecord) private reports;

    event ReportCommitted(
        bytes32 indexed reportId,
        bytes32 reportHash,
        address indexed reporter,
        uint256 revision,
        uint256 timestamp
    );

    event StatusUpdated(
        bytes32 indexed reportId,
        Status newStatus,
        address indexed updater,
        uint256 timestamp
    );

    function commitReport(bytes32 reportId, bytes32 reportHash) external {
        require(reportHash != bytes32(0), "Zero report hash rejected");
        require(reportId != bytes32(0), "Zero report identifier rejected");

        ReportRecord storage record = reports[reportId];

        if (record.timestamp == 0) {
            // New report record
            record.reportHash = reportHash;
            record.timestamp = block.timestamp;
            record.reporter = msg.sender;
            record.status = Status.Reported;
            record.revision = 1;

            emit ReportCommitted(reportId, reportHash, msg.sender, 1, block.timestamp);
        } else {
            // Revision: only original reporter can update
            require(msg.sender == record.reporter, "Only original reporter can revise report");

            record.reportHash = reportHash;
            record.timestamp = block.timestamp;
            record.status = Status.Reported;
            record.revision += 1;

            emit ReportCommitted(reportId, reportHash, msg.sender, record.revision, block.timestamp);
        }
    }

    function updateStatus(bytes32 reportId, Status newStatus) external {
        ReportRecord storage record = reports[reportId];
        require(record.timestamp != 0, "Unknown report identifier");
        require(msg.sender != record.reporter, "Reporter cannot validate their own report");

        record.status = newStatus;
        emit StatusUpdated(reportId, newStatus, msg.sender, block.timestamp);
    }

    function getReport(bytes32 reportId) external view returns (
        bytes32 reportHash,
        uint256 timestamp,
        address reporter,
        Status status,
        uint256 revision
    ) {
        ReportRecord memory r = reports[reportId];
        require(r.timestamp != 0, "Report does not exist");
        return (r.reportHash, r.timestamp, r.reporter, r.status, r.revision);
    }

    function reportExists(bytes32 reportId) external view returns (bool) {
        return reports[reportId].timestamp != 0;
    }
}
