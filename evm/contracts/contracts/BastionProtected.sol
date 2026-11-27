// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BastionGuard} from "./BastionGuard.sol";

/// @title BastionProtected
/// @notice Inherit this to put a contract behind the Bastion firewall.
///         - add `whenBastionActive` to state-changing entry points
///         - call `_bastionOutflow(token, amount)` immediately before any value leaves the contract
abstract contract BastionProtected {
    BastionGuard public immutable bastion;

    constructor(BastionGuard guard, address bastionAdmin) {
        bastion = guard;
        guard.register(bastionAdmin);
    }

    modifier whenBastionActive() {
        bastion.checkNotPaused();
        _;
    }

    function _bastionOutflow(address token, uint256 amount) internal {
        bastion.checkOutflow(token, amount);
    }
}
