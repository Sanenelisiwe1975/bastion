import { parseAbi } from "viem";

export const erc20Abi = parseAbi([
  "event Transfer(address indexed from, address indexed to, uint256 value)",
  "function balanceOf(address) view returns (uint256)",
]);

/** Privileged events from OpenZeppelin patterns that should never happen silently. */
export const privilegedAbi = parseAbi([
  "event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)",
  "event Upgraded(address indexed implementation)",
  "event AdminChanged(address previousAdmin, address newAdmin)",
  "event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender)",
  "event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender)",
  "event BeaconUpgraded(address indexed beacon)",
]);

export const bastionGuardAbi = parseAbi([
  "event Registered(address indexed protected, address indexed admin)",
  "event AdminTransferred(address indexed protected, address indexed previousAdmin, address indexed newAdmin)",
  "event GuardianSet(address indexed protected, address indexed guardian, bool enabled)",
  "event Paused(address indexed protected, address indexed by, string reason)",
  "event Unpaused(address indexed protected, address indexed by)",
  "event OutflowLimitSet(address indexed protected, address indexed token, uint256 capacity, uint256 window)",
  "event OutflowLimitRemoved(address indexed protected, address indexed token)",
  "event Outflow(address indexed protected, address indexed token, uint256 amount, uint256 remaining)",
  "function pause(address protected, string reason)",
  "function isPaused(address protected) view returns (bool)",
  "function isGuardian(address protected, address guardian) view returns (bool)",
]);

/** Avalanche Interchain Messaging (Teleporter) — v1 event layout. */
export const teleporterAbi = parseAbi([
  "struct TeleporterMessageReceipt { uint256 receivedMessageNonce; address relayerRewardAddress; }",
  "struct TeleporterMessage { uint256 messageNonce; address originSenderAddress; bytes32 destinationBlockchainID; address destinationAddress; uint256 requiredGasLimit; address[] allowedRelayerAddresses; TeleporterMessageReceipt[] receipts; bytes message; }",
  "event ReceiveCrossChainMessage(bytes32 indexed messageID, bytes32 indexed sourceBlockchainID, address indexed deliverer, address rewardRedeemer, TeleporterMessage message)",
]);
