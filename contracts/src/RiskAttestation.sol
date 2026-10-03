// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @title RiskAttestation
/// @notice A public record of risk checks on Arc, made with web3-risk-mcp and
/// Arc Safe Send. Anyone can save a check about an address. Every record keeps
/// who saved it, so readers decide whose checks they trust.
/// @dev The contract has no owner, holds no money, and cannot be changed after
/// it is deployed. None of its functions accept USDC, so USDC sent to it by
/// mistake is refused instead of being lost.
contract RiskAttestation {
    /// @notice One saved check.
    /// @param score The risk score, from 0 (no red flags) to 100.
    /// @param rulesVersion The version of the public rule table that made the score.
    /// @param timestamp The block time when the check was saved.
    /// @param findingsHash keccak256 of the findings, so anyone can verify them.
    struct Attestation {
        uint8 score;
        uint16 rulesVersion;
        uint64 timestamp;
        bytes32 findingsHash;
    }

    /// @dev The latest check each attester saved for each address.
    mapping(address attester => mapping(address subject => Attestation)) private _latest;

    /// @notice How many checks have been saved in total.
    uint256 public totalAttestations;

    /// @notice Emitted for every saved check, so the full history can be read from logs.
    event Attested(
        address indexed attester,
        address indexed subject,
        uint8 score,
        uint16 rulesVersion,
        bytes32 findingsHash,
        uint64 timestamp
    );

    error EmptySubject();
    error ScoreAbove100(uint8 score);
    error EmptyRulesVersion();
    error EmptyFindingsHash();

    /// @notice Save a risk check about `subject`. The caller is recorded as the attester.
    function attest(address subject, uint8 score, uint16 rulesVersion, bytes32 findingsHash) external {
        if (subject == address(0)) revert EmptySubject();
        if (score > 100) revert ScoreAbove100(score);
        if (rulesVersion == 0) revert EmptyRulesVersion();
        if (findingsHash == bytes32(0)) revert EmptyFindingsHash();

        uint64 savedAt = uint64(block.timestamp);
        _latest[msg.sender][subject] = Attestation(score, rulesVersion, savedAt, findingsHash);
        unchecked {
            ++totalAttestations;
        }
        emit Attested(msg.sender, subject, score, rulesVersion, findingsHash, savedAt);
    }

    /// @notice The latest check `attester` saved about `subject`. All fields are
    /// zero if there is none.
    function latest(address attester, address subject) external view returns (Attestation memory) {
        return _latest[attester][subject];
    }
}
