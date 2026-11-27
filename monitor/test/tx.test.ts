import { describe, expect, it } from "vitest";
import {
  Keypair,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
  type VersionedTransactionResponse,
} from "@solana/web3.js";
import {
  BPF_UPGRADEABLE_LOADER_ID,
  DEMO_VAULT_PROGRAM_ID,
  GUARD_PROGRAM_ID,
  encodeEvent,
  programDataAddress,
} from "../src/bastion.js";
import { toTxRecord } from "../src/tx.js";

const k = () => Keypair.generate().publicKey;

function response(ixs: TransactionInstruction[], meta: Partial<NonNullable<VersionedTransactionResponse["meta"]>>) {
  const payer = k();
  const msg = new TransactionMessage({ payerKey: payer, recentBlockhash: k().toBase58(), instructions: ixs }).compileToV0Message();
  const tx = new VersionedTransaction(msg);
  const keys = msg.staticAccountKeys;
  return {
    keys,
    res: {
      slot: 42,
      blockTime: 1_700_000_000,
      transaction: { message: msg, signatures: ["s"] },
      meta: { err: null, fee: 5000, preBalances: [], postBalances: [], logMessages: [], ...meta },
      version: 0,
    } as unknown as VersionedTransactionResponse,
    tx,
  };
}

describe("toTxRecord", () => {
  it("extracts token deltas, guard events and loader upgrades", () => {
    const vaultTokens = k();
    const dest = k();
    const upgrade = new TransactionInstruction({
      programId: BPF_UPGRADEABLE_LOADER_ID,
      keys: [programDataAddress(DEMO_VAULT_PROGRAM_ID), DEMO_VAULT_PROGRAM_ID].map((pubkey) => ({ pubkey, isSigner: false, isWritable: true })),
      data: Buffer.from([3, 0, 0, 0]),
    });
    const sweep = new TransactionInstruction({
      programId: DEMO_VAULT_PROGRAM_ID,
      keys: [vaultTokens, dest].map((pubkey) => ({ pubkey, isSigner: false, isWritable: true })),
      data: Buffer.alloc(0),
    });
    const { keys, res } = response([upgrade, sweep], {});
    const vi = keys.findIndex((x) => x.equals(vaultTokens));
    const di = keys.findIndex((x) => x.equals(dest));
    const mint = k().toBase58();
    const bal = (accountIndex: number, amount: string) =>
      ({ accountIndex, mint, owner: "o", uiTokenAmount: { amount, decimals: 6, uiAmount: null, uiAmountString: "" } });
    const ev = { name: "Outflow", protected: k(), mint: k(), amount: 100n, remaining: 0n } as const;
    res.meta!.preTokenBalances = [bal(vi, "1000"), bal(di, "0")];
    res.meta!.postTokenBalances = [bal(vi, "900"), bal(di, "100")];
    res.meta!.logMessages = [
      `Program ${DEMO_VAULT_PROGRAM_ID} invoke [1]`, `Program ${GUARD_PROGRAM_ID} invoke [2]`,
      `Program data: ${encodeEvent(ev).toString("base64")}`, `Program ${GUARD_PROGRAM_ID} success`,
      `Program ${DEMO_VAULT_PROGRAM_ID} success`,
    ];

    const rec = toTxRecord("sig", res, GUARD_PROGRAM_ID);
    expect(rec.failed).toBe(false);
    expect(rec.tokenDeltas).toEqual(expect.arrayContaining([
      expect.objectContaining({ account: vaultTokens.toBase58(), delta: -100n }),
      expect.objectContaining({ account: dest.toBase58(), delta: 100n }),
    ]));
    expect(rec.events).toEqual([ev]);
    expect(rec.loaderActions).toEqual([{
      kind: "Upgrade", programData: programDataAddress(DEMO_VAULT_PROGRAM_ID).toBase58(), program: DEMO_VAULT_PROGRAM_ID.toBase58(),
    }]);
  });
});
