// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {RiskAttestation} from "../src/RiskAttestation.sol";
import {DeployRiskAttestation} from "../script/DeployRiskAttestation.s.sol";

contract RiskAttestationTest is Test {
    RiskAttestation internal registry;

    address internal constant ALICE = address(0xA11CE);
    address internal constant BOB = address(0xB0B);
    address internal constant SUBJECT = 0x7F367cC41522cE07553e823bf3be79A889DEbe1B;
    bytes32 internal constant HASH =
        bytes32(uint256(0x1111111111111111111111111111111111111111111111111111111111111111));

    event Attested(
        address indexed attester,
        address indexed subject,
        uint8 score,
        uint16 rulesVersion,
        bytes32 findingsHash,
        uint64 timestamp
    );

    function setUp() public {
        registry = new RiskAttestation();
        vm.warp(1_791_000_000);
    }

    function test_SavesTheCheckAndWhoSavedIt() public {
        vm.expectEmit(true, true, false, true, address(registry));
        emit Attested(ALICE, SUBJECT, 100, 3, HASH, 1_791_000_000);

        vm.prank(ALICE);
        registry.attest(SUBJECT, 100, 3, HASH);

        RiskAttestation.Attestation memory a = registry.latest(ALICE, SUBJECT);
        assertEq(a.score, 100);
        assertEq(a.rulesVersion, 3);
        assertEq(a.timestamp, 1_791_000_000);
        assertEq(a.findingsHash, HASH);
        assertEq(registry.totalAttestations(), 1);
    }

    function test_NewerCheckReplacesOlderOneFromTheSameAttester() public {
        vm.prank(ALICE);
        registry.attest(SUBJECT, 100, 3, HASH);
        vm.warp(1_791_000_100);
        vm.prank(ALICE);
        registry.attest(SUBJECT, 40, 4, bytes32(uint256(2)));

        RiskAttestation.Attestation memory a = registry.latest(ALICE, SUBJECT);
        assertEq(a.score, 40);
        assertEq(a.rulesVersion, 4);
        assertEq(a.timestamp, 1_791_000_100);
        assertEq(registry.totalAttestations(), 2);
    }

    function test_EachAttesterKeepsTheirOwnRecord() public {
        vm.prank(ALICE);
        registry.attest(SUBJECT, 100, 3, HASH);
        vm.prank(BOB);
        registry.attest(SUBJECT, 10, 3, HASH);

        assertEq(registry.latest(ALICE, SUBJECT).score, 100);
        assertEq(registry.latest(BOB, SUBJECT).score, 10);
        assertEq(registry.latest(address(0xCAFE), SUBJECT).timestamp, 0); // nothing saved
    }

    function test_RejectsBadInput() public {
        vm.expectRevert(RiskAttestation.EmptySubject.selector);
        registry.attest(address(0), 50, 3, HASH);

        vm.expectRevert(abi.encodeWithSelector(RiskAttestation.ScoreAbove100.selector, uint8(101)));
        registry.attest(SUBJECT, 101, 3, HASH);

        vm.expectRevert(RiskAttestation.EmptyRulesVersion.selector);
        registry.attest(SUBJECT, 50, 0, HASH);

        vm.expectRevert(RiskAttestation.EmptyFindingsHash.selector);
        registry.attest(SUBJECT, 50, 3, bytes32(0));

        assertEq(registry.totalAttestations(), 0);
    }

    function test_RefusesUsdcSoNobodyLosesMoneyInIt() public {
        vm.deal(address(this), 1 ether);

        (bool plainSend,) = address(registry).call{value: 1}("");
        assertFalse(plainSend, "a plain USDC send must be refused");

        bytes memory data = abi.encodeCall(RiskAttestation.attest, (SUBJECT, 50, 3, HASH));
        (bool paidCall,) = address(registry).call{value: 1}(data);
        assertFalse(paidCall, "attest must not accept USDC");

        assertEq(address(registry).balance, 0);
    }

    function testFuzz_AnyValidCheckIsStored(address attester, address subject, uint8 score, uint16 version, bytes32 h)
        public
    {
        vm.assume(subject != address(0) && version != 0 && h != bytes32(0));
        score = uint8(bound(score, 0, 100));

        vm.prank(attester);
        registry.attest(subject, score, version, h);

        RiskAttestation.Attestation memory a = registry.latest(attester, subject);
        assertEq(a.score, score);
        assertEq(a.rulesVersion, version);
        assertEq(a.findingsHash, h);
    }

    /// The web app builds this exact data in Python (web3_risk_mcp.attestation).
    /// If the contract's function changes, this test and the Python test fail together.
    function test_CallDataMatchesWhatTheWebAppSends() public pure {
        bytes memory expected =
            hex"de93cefc0000000000000000000000007f367cc41522ce07553e823bf3be79a889debe1b000000000000000000000000000000000000000000000000000000000000006400000000000000000000000000000000000000000000000000000000000000031111111111111111111111111111111111111111111111111111111111111111";
        assertEq(abi.encodeCall(RiskAttestation.attest, (SUBJECT, 100, 3, HASH)), expected);
        assertEq(
            RiskAttestation.Attested.selector,
            bytes32(0x8062d723a0dd5e8f6d90f6766cd0bc32e097dbb36b3f13aea4de87c2b4469876)
        );
    }

    function test_DeployScriptDeploysAWorkingContract() public {
        RiskAttestation deployed = new DeployRiskAttestation().run();
        assertGt(address(deployed).code.length, 0);
        assertEq(deployed.totalAttestations(), 0);
    }
}
