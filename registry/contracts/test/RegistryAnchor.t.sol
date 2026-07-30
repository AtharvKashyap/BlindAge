// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {TimelockController} from "openzeppelin-contracts/contracts/governance/TimelockController.sol";
import {RegistryAnchor} from "../src/RegistryAnchor.sol";

contract RegistryAnchorTest is Test {
    TimelockController timelock;
    RegistryAnchor anchor;
    address ops = address(0xA11CE);
    uint256 constant DELAY = 100;

    event AnchorUpdated(bytes32 registryHash, string generatedAt, uint64 version);

    function setUp() public {
        address[] memory proposers = new address[](1);
        proposers[0] = ops;
        address[] memory executors = new address[](1);
        executors[0] = ops;
        timelock = new TimelockController(DELAY, proposers, executors, address(0));
        anchor = new RegistryAnchor(address(timelock));
    }

    function test_update_through_timelock_after_delay() public {
        // Schedule and warp first: the timelock emits CallScheduled during
        // schedule(), so expectEmit is placed right before execute(), where the
        // very next emitted log is AnchorUpdated (emitted inside _execute before
        // the timelock's own CallExecuted).
        bytes memory data = abi.encodeCall(
            RegistryAnchor.setAnchor, (bytes32(uint256(1)), "2026-07-30T00:00:00Z", uint64(1))
        );
        vm.prank(ops);
        timelock.schedule(address(anchor), 0, data, bytes32(0), bytes32(uint256(1)), DELAY);
        vm.warp(block.timestamp + DELAY);
        vm.expectEmit();
        emit AnchorUpdated(bytes32(uint256(1)), "2026-07-30T00:00:00Z", 1);
        vm.prank(ops);
        timelock.execute(address(anchor), 0, data, bytes32(0), bytes32(uint256(1)));
        (bytes32 h, string memory g, uint64 v, uint64 u) = anchor.current();
        assertEq(h, bytes32(uint256(1)));
        assertEq(g, "2026-07-30T00:00:00Z");
        assertEq(v, 1);
        assertGt(u, 0);
    }

    function test_execute_before_delay_reverts() public {
        bytes memory data = abi.encodeCall(
            RegistryAnchor.setAnchor, (bytes32(uint256(1)), "2026-07-30T00:00:00Z", uint64(1))
        );
        vm.prank(ops);
        timelock.schedule(address(anchor), 0, data, bytes32(0), bytes32(0), DELAY);
        vm.prank(ops);
        vm.expectRevert(); // TimelockUnexpectedOperationState
        timelock.execute(address(anchor), 0, data, bytes32(0), bytes32(0));
    }

    function test_direct_setAnchor_reverts() public {
        vm.expectRevert(RegistryAnchor.NotTimelock.selector);
        anchor.setAnchor(bytes32(uint256(1)), "2026-07-30T00:00:00Z", 1);
    }

    function test_version_rollback_reverts() public {
        vm.startPrank(address(timelock));
        anchor.setAnchor(bytes32(uint256(2)), "2026-07-30T00:00:00Z", 2);
        vm.expectRevert(RegistryAnchor.VersionNotIncreasing.selector);
        anchor.setAnchor(bytes32(uint256(3)), "2026-07-31T00:00:00Z", 2);
        vm.stopPrank();
    }

    function test_generatedAt_rollback_reverts() public {
        vm.startPrank(address(timelock));
        anchor.setAnchor(bytes32(uint256(2)), "2026-07-30T00:00:00Z", 2);
        vm.expectRevert(RegistryAnchor.GeneratedAtNotIncreasing.selector);
        anchor.setAnchor(bytes32(uint256(3)), "2026-07-29T00:00:00Z", 3);
        // equal generatedAt also rejected (strict)
        vm.expectRevert(RegistryAnchor.GeneratedAtNotIncreasing.selector);
        anchor.setAnchor(bytes32(uint256(3)), "2026-07-30T00:00:00Z", 3);
        vm.stopPrank();
    }
}
