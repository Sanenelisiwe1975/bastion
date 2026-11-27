// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title BastionGuard
/// @notice Shared onchain firewall for Avalanche C-Chain and L1s. Deploy one per chain.
///         Protected contracts register themselves and call the guard before value leaves them.
///         Two layers of defence:
///           1. Circuit breaker: guardians (monitor bots) can pause a protected contract instantly.
///              Only the protocol admin can unpause, so a compromised guardian key can halt but never steal.
///           2. Outflow rate limits: a refilling token bucket per (protected contract, token) caps how much
///              can leave in a time window, bounding the loss from any bug the auditors missed.
contract BastionGuard {
    /// @dev address(0) represents native AVAX (or the L1's native gas token).
    address public constant NATIVE = address(0);

    struct Bucket {
        uint128 capacity; // max amount that can leave in one full window
        uint64 window; // seconds to fully refill
        uint128 available; // amount currently allowed to leave
        uint64 lastUpdate; // timestamp of last refill
    }

    struct Protection {
        address admin; // protocol multisig / timelock
        bool registered;
        bool paused;
    }

    mapping(address protected => Protection) public protections;
    mapping(address protected => mapping(address guardian => bool)) public isGuardian;
    mapping(address protected => mapping(address token => Bucket)) public buckets;

    event Registered(address indexed protected, address indexed admin);
    event AdminTransferred(address indexed protected, address indexed previousAdmin, address indexed newAdmin);
    event GuardianSet(address indexed protected, address indexed guardian, bool enabled);
    event Paused(address indexed protected, address indexed by, string reason);
    event Unpaused(address indexed protected, address indexed by);
    event OutflowLimitSet(address indexed protected, address indexed token, uint256 capacity, uint256 window);
    event OutflowLimitRemoved(address indexed protected, address indexed token);
    event Outflow(address indexed protected, address indexed token, uint256 amount, uint256 remaining);

    error AlreadyRegistered();
    error NotRegistered();
    error NotAdmin();
    error NotGuardianOrAdmin();
    error ProtocolPaused(address protected);
    error OutflowLimitExceeded(address protected, address token, uint256 requested, uint256 available);
    error InvalidLimit();
    error ZeroAddress();

    modifier onlyAdmin(address protected) {
        if (protections[protected].admin != msg.sender) revert NotAdmin();
        _;
    }

    // ---------------------------------------------------------------------
    // Registration (called by the protected contract itself, e.g. in its constructor)
    // ---------------------------------------------------------------------

    function register(address admin) external {
        if (admin == address(0)) revert ZeroAddress();
        Protection storage p = protections[msg.sender];
        if (p.registered) revert AlreadyRegistered();
        p.registered = true;
        p.admin = admin;
        emit Registered(msg.sender, admin);
    }

    // ---------------------------------------------------------------------
    // Admin configuration
    // ---------------------------------------------------------------------

    function transferAdmin(address protected, address newAdmin) external onlyAdmin(protected) {
        if (newAdmin == address(0)) revert ZeroAddress();
        emit AdminTransferred(protected, msg.sender, newAdmin);
        protections[protected].admin = newAdmin;
    }

    function setGuardian(address protected, address guardian, bool enabled) external onlyAdmin(protected) {
        if (guardian == address(0)) revert ZeroAddress();
        isGuardian[protected][guardian] = enabled;
        emit GuardianSet(protected, guardian, enabled);
    }

    /// @notice Cap outflows of `token` from `protected` to `capacity` per `window` seconds (linear refill).
    function setOutflowLimit(address protected, address token, uint128 capacity, uint64 window)
        external
        onlyAdmin(protected)
    {
        if (capacity == 0 || window == 0) revert InvalidLimit();
        buckets[protected][token] =
            Bucket({capacity: capacity, window: window, available: capacity, lastUpdate: uint64(block.timestamp)});
        emit OutflowLimitSet(protected, token, capacity, window);
    }

    function removeOutflowLimit(address protected, address token) external onlyAdmin(protected) {
        delete buckets[protected][token];
        emit OutflowLimitRemoved(protected, token);
    }

    // ---------------------------------------------------------------------
    // Circuit breaker
    // ---------------------------------------------------------------------

    /// @notice Guardians or the admin can halt a protocol. Guardians cannot unpause.
    function pause(address protected, string calldata reason) external {
        Protection storage p = protections[protected];
        if (!p.registered) revert NotRegistered();
        if (msg.sender != p.admin && !isGuardian[protected][msg.sender]) revert NotGuardianOrAdmin();
        p.paused = true;
        emit Paused(protected, msg.sender, reason);
    }

    function unpause(address protected) external onlyAdmin(protected) {
        protections[protected].paused = false;
        emit Unpaused(protected, msg.sender);
    }

    // ---------------------------------------------------------------------
    // Hooks called by protected contracts (msg.sender is the protected contract)
    // ---------------------------------------------------------------------

    function checkNotPaused() external view {
        if (protections[msg.sender].paused) revert ProtocolPaused(msg.sender);
    }

    /// @notice Records an outflow and reverts if the protocol is paused or the rate limit is exceeded.
    ///         Tokens with no configured limit pass through (still subject to pause).
    function checkOutflow(address token, uint256 amount) external {
        Protection storage p = protections[msg.sender];
        if (!p.registered) revert NotRegistered();
        if (p.paused) revert ProtocolPaused(msg.sender);

        Bucket storage b = buckets[msg.sender][token];
        if (b.capacity == 0) return; // no limit configured

        uint256 available = _refilled(b);
        if (amount > available) revert OutflowLimitExceeded(msg.sender, token, amount, available);

        unchecked {
            available -= amount;
        }
        b.available = uint128(available);
        b.lastUpdate = uint64(block.timestamp);
        emit Outflow(msg.sender, token, amount, available);
    }

    // ---------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------

    function availableOutflow(address protected, address token) external view returns (uint256) {
        Bucket storage b = buckets[protected][token];
        if (b.capacity == 0) return type(uint256).max;
        return _refilled(b);
    }

    function isPaused(address protected) external view returns (bool) {
        return protections[protected].paused;
    }

    function _refilled(Bucket storage b) private view returns (uint256) {
        uint256 elapsed = block.timestamp - b.lastUpdate;
        uint256 refill = (elapsed * b.capacity) / b.window;
        uint256 total = uint256(b.available) + refill;
        return total > b.capacity ? b.capacity : total;
    }
}
