# @limccn/longstone-wallet

The single implementation of the MemoryOverEth `wallet.v1` record. The Chrome/
Edge extension consumes it today; the VS Code extension has the workspace
dependency wired and adopts it as the wallet work lands. Neither host may own a
second copy of the crypto, the record format, the derivation or the vault
lifecycle.

## What it owns

- **Format** — strict `wallet.v1` envelope parsing (`format`, `version`,
  `domain`) and payload invariants (1–50 accounts, unique ids and addresses,
  EIP-55, `source` consistent with `secret.kind`, sanitized labels, a live
  `activeAccountId`, bounded ciphertext and secrets).
- **Crypto** — Argon2id (domain-tagged preimage, whitelisted cost ladder),
  HKDF-SHA-256 (`longstone/wallet.v1/enc`) and AES-256-GCM with a fresh 12-byte
  IV per write. The vault key is a non-extractable `CryptoKey`.
- **Accounts** — BIP-39 generation/import (12/15/18/21/24 English words),
  `m/44'/60'/0'/0/0` derivation and EIP-55 addresses through
  `@scure/bip39`, `@scure/bip32`, `@noble/curves` and `@noble/hashes`.
- **Password policy** — NFC normalization, 8–1024 Unicode codepoints, a
  non-gating strength hint. Passwords are never trimmed or collapsed.
- **Vault lifecycle** — `loadVault`, `createVault`, `unlockVault`, `saveVault`,
  `changePassword` (two-phase `pending` with recovery), `resetVault`,
  `deleteAccount` (the last account deletes the vault), and the account
  operations. Writes carry the hash of the record they were derived from.
- **Lock primitives** — `createLockController` (injected clock, idle/hidden
  policy) and `createEpochGate` (discard results from an older session).

## What it never does

- **No signing.** No `sign*` API, no `viem/accounts`, no transaction or message
  objects. This package can derive an address and reveal a key; it cannot use
  one.
- **No host storage.** Storage, clock and randomness are injected through
  `VaultDeps`. Hosts map the exported logical keys (`RECORD_KEY`,
  `PENDING_KEY`) to their own namespace (the browser uses
  `longstone-ext.wallet.v1`; VS Code uses `longstone.wallet.v1`).
- **No network, DOM or console.** No `fetch`, no `chrome.*`, no `document`,
  no `window`, no `vscode`, no Node built-ins, no logging. The purity test
  scans the sources and fails on any of them.
- **No plaintext on disk.** Callers hand the vault a password and storage
  adapter; the only thing written is the encrypted record.

## Install

```bash
pnpm add @limccn/longstone-wallet
```

Node >= 24. ESM only, with bundled type declarations. Runtime dependencies are
pinned exactly: `@noble/curves 1.9.1`, `@noble/hashes 1.8.0`,
`@scure/bip32 1.7.0`, `@scure/bip39 1.6.0`, `hash-wasm 4.12.0`.

## Use

```ts
import {
  DEFAULT_STORAGE_KEYS,
  createVault,
  createLockController,
  loadVault,
  unlockVault,
  type WalletStorage,
} from '@limccn/longstone-wallet';

const storage: WalletStorage = {
  async get(key) { return { [key]: await host.read(key) }; },
  async set(items) { for (const [key, value] of Object.entries(items)) await host.write(key, value); },
  async remove(key) { await host.remove(key); },
};

const deps = { storage, keys: DEFAULT_STORAGE_KEYS };

const state = await loadVault(deps); // { kind: 'NO_VAULT' | 'LOCKED' | 'CORRUPT' }
if (state.kind === 'NO_VAULT') {
  const created = await createVault(deps, {
    password,
    account: { source: 'mnemonic', secret: { kind: 'mnemonic', words } },
  });
  if (!created.ok) throw created.error;
}
const unlocked = await unlockVault(deps, password);
if (!unlocked.ok) throw unlocked.error;
```

Every vault function returns a typed result (`VaultResult<T>` or
`ChangePasswordResult`) whose error carries only a `WalletErrorCode` and
non-sensitive details — never the password, a mnemonic word or key material.
Hosts own the session, the UI copy, the storage namespace and the lock timing;
the core only enforces the record and crypto invariants.

## Development

```bash
pnpm install
pnpm build       # tsc -> dist/ (ESM + .d.ts)
pnpm test        # vitest run (golden vectors, round-trips, tamper, two-phase change)
pnpm typecheck
npm pack --dry-run
```

`scripts/spike/entry.ts` is the Phase 0 hash-wasm bundling spike: esbuild
bundles it for Node CJS and the result is run under Node 24 to record bundle
size, emitted `.wasm` files and KDF timing.

## License

Apache-2.0.
