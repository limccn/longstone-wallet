/**
 * Vault lifecycle (design §5, §7; AC-2..AC-4, AC-8, AC-14..AC-24).
 *
 * Every flow runs against an in-memory storage and a cheap KDF stand-in; the
 * real Argon2id vector is pinned in `crypto.test.ts`. This file cares about
 * what is written, when, and what happens when a write is interrupted.
 */
import { describe, expect, it } from 'vitest';
import type { KdfParams } from '../src/index.js';
import { bytesToBase64 } from '../src/index.js';
import { privateKeyToAddress } from '../src/index.js';
import { MAX_ACCOUNTS } from '../src/index.js';
import { WalletError } from '../src/index.js';
import type {
  NewAccountInput,
  UnlockOutcome,
  UnlockedVault,
  VaultDeps,
  VaultPayload,
  VaultResult,
} from '../src/index.js';
import {
  DEFAULT_IDLE_TIMEOUT_MS,
  addAccount,
  changePassword,
  createVault,
  deleteAccount,
  loadVault,
  renameAccount,
  resetVault,
  saveVault,
  setActiveAccount,
  setIdleTimeout,
  unlockVault,
} from '../src/index.js';
import { FaultyStorage, MemoryStorage, TEST_KEYS, counterRng, fastArgon2 } from './helpers.js';

const PASSWORD = 'correct horse battery staple';
const MNEMONIC_A = 'test test test test test test test test test test test junk';
const ADDRESS_A = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const KEY_A = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const KEY_B = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';
const ADDRESS_B = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const TS = 1_700_000_000_000;

interface Harness {
  deps: VaultDeps;
  storage: MemoryStorage;
  clock: { value: number };
}

function makeHarness(storage: MemoryStorage = new MemoryStorage()): Harness {
  const clock = { value: TS };
  return {
    storage,
    clock,
    deps: {
      storage,
      keys: TEST_KEYS,
      now: () => clock.value,
      rng: counterRng(),
      argon2: fastArgon2,
    },
  };
}

function mnemonicAccount(): NewAccountInput {
  return { source: 'mnemonic', secret: { kind: 'mnemonic', words: MNEMONIC_A } };
}

async function create(harness: Harness, password = PASSWORD): Promise<UnlockedVault> {
  const result = await createVault(harness.deps, { password, account: mnemonicAccount() });
  if (!result.ok) throw result.error;
  return result.value;
}

function expectError<T>(result: VaultResult<T>, code: string): void {
  expect(result.ok).toBe(false);
  if (!result.ok) expect(result.error.code).toBe(code);
}

async function unlock(harness: Harness, password = PASSWORD): Promise<UnlockOutcome> {
  const result = await unlockVault(harness.deps, password);
  if (!result.ok) throw result.error;
  return result.value;
}

function recordOf(harness: Harness): Record<string, unknown> {
  const record = harness.storage.data.get(TEST_KEYS.record);
  expect(record).toBeTypeOf('object');
  return record as Record<string, unknown>;
}

function kdfOf(record: Record<string, unknown>): KdfParams {
  const kdf = record['kdf'] as { m: number; t: number; p: number };
  return { m: kdf.m, t: kdf.t, p: kdf.p };
}

describe('create', () => {
  it('writes exactly one opaque record and returns an unlocked vault', async () => {
    const harness = makeHarness();
    const vault = await create(harness);

    expect(harness.storage.data.has(TEST_KEYS.record)).toBe(true);
    expect(harness.storage.data.has(TEST_KEYS.pending)).toBe(false);
    expect(vault.payload.accounts).toHaveLength(1);
    expect(vault.payload.accounts[0]).toMatchObject({
      address: ADDRESS_A,
      source: 'mnemonic',
      label: 'Account 1',
      secret: { kind: 'mnemonic', words: MNEMONIC_A },
    });
    expect(vault.payload.activeAccountId).toBe(vault.payload.accounts[0]?.id);
    expect(vault.payload.idleTimeoutMs).toBe(DEFAULT_IDLE_TIMEOUT_MS);
    expect(vault.kdf).toEqual({ m: 65536, t: 3, p: 1 });

    const serialized = harness.storage.dump();
    expect(serialized).not.toContain(MNEMONIC_A);
    expect(serialized).not.toContain('test test');
    expect(serialized).not.toContain(KEY_A);
    expect(serialized).toContain('longstone.wallet.v1');
    const record = recordOf(harness);
    expect((record['kdf'] as { salt: string }).salt.length).toBeGreaterThan(0);
    expect(JSON.parse(serialized)).toBeTypeOf('object');
  });

  it('falls back down the KDF ladder only on KDF_UNAVAILABLE', async () => {
    const ladder: Array<{ threshold: number; expected: KdfParams }> = [
      { threshold: 65537, expected: { m: 65536, t: 3, p: 1 } },
      { threshold: 65536, expected: { m: 32768, t: 3, p: 1 } },
      { threshold: 32768, expected: { m: 19456, t: 2, p: 1 } },
    ];
    for (const { threshold, expected } of ladder) {
      const harness = makeHarness();
      harness.deps.argon2 = async (input) => {
        if (input.params.m >= threshold) throw new WalletError('KDF_UNAVAILABLE');
        return fastArgon2(input);
      };
      const vault = await create(harness);
      expect(vault.kdf).toEqual(expected);
      expect(kdfOf(recordOf(harness))).toEqual(expected);
      await expect(unlock(harness)).resolves.toMatchObject({ vault: { kdf: expected } });
    }
  });

  it('reports KDF_UNAVAILABLE when the whole ladder fails, with no record written', async () => {
    const harness = makeHarness();
    harness.deps.argon2 = async () => {
      throw new WalletError('KDF_UNAVAILABLE');
    };
    const result = await createVault(harness.deps, { password: PASSWORD, account: mnemonicAccount() });
    expectError(result, 'KDF_UNAVAILABLE');
    expect(harness.storage.data.size).toBe(0);
  });

  it('refuses to overwrite an existing record or a lone pending record', async () => {
    const harness = makeHarness();
    await create(harness);
    expectError(
      await createVault(harness.deps, { password: PASSWORD, account: mnemonicAccount() }),
      'VAULT_EXISTS',
    );

    const pendingOnly = makeHarness();
    await create(pendingOnly);
    pendingOnly.storage.data.set(TEST_KEYS.pending, pendingOnly.storage.data.get(TEST_KEYS.record));
    pendingOnly.storage.data.delete(TEST_KEYS.record);
    expectError(
      await createVault(pendingOnly.deps, { password: PASSWORD, account: mnemonicAccount() }),
      'VAULT_EXISTS',
    );
  });

  it('rechecks both keys immediately before writing the primary record', async () => {
    for (const key of [TEST_KEYS.record, TEST_KEYS.pending] as const) {
      const storage = new FaultyStorage();
      const harness = makeHarness(storage);
      const rivalHarness = makeHarness();
      await create(rivalHarness, 'rival password');
      const rivalRaw = rivalHarness.storage.data.get(TEST_KEYS.record);

      // Read #1 is the entry check; read #2 is the pre-write recheck. A rival
      // create landing during our KDF must be detected before we write.
      let reads = 0;
      storage.beforeGet = (readKey) => {
        if (readKey !== key) return;
        reads += 1;
        if (reads === 2) storage.data.set(key, rivalRaw);
      };

      expectError(
        await createVault(harness.deps, { password: PASSWORD, account: mnemonicAccount() }),
        'VAULT_EXISTS',
      );
      expect(storage.writes).toEqual([]);
      expect(storage.data.get(key)).toBe(rivalRaw);
    }
  });

  it('validates the password before doing any KDF or storage work', async () => {
    const harness = makeHarness();
    let kdfCalls = 0;
    const original = harness.deps.argon2;
    harness.deps.argon2 = async (input) => {
      kdfCalls += 1;
      return original?.(input) ?? new Uint8Array(32);
    };
    expectError(
      await createVault(harness.deps, { password: 'short', account: mnemonicAccount() }),
      'TOO_SHORT',
    );
    expect(kdfCalls).toBe(0);
    expect(harness.storage.data.size).toBe(0);
  });
});

describe('unlock and load', () => {
  it('classifies absent, present and corrupt storage states', async () => {
    const empty = makeHarness();
    expect(await loadVault(empty.deps)).toEqual({ kind: 'NO_VAULT' });

    const harness = makeHarness();
    const vault = await create(harness);
    const loaded = await loadVault(harness.deps);
    expect(loaded).toMatchObject({
      kind: 'LOCKED',
      pendingOnly: false,
      primaryCorrupt: false,
      recordHash: vault.recordHash,
      kdf: { m: 65536, t: 3, p: 1 },
    });

    harness.storage.data.set(TEST_KEYS.record, { nonsense: true });
    expect(await loadVault(harness.deps)).toEqual({ kind: 'CORRUPT', pendingOnly: false });
  });

  it('unlocks with the right password and writes nothing on failure', async () => {
    const harness = makeHarness();
    const created = await create(harness);
    const writesBefore = harness.storage.writes.length;

    const unlocked = await unlock(harness);
    expect(unlocked.recoveredFromPending).toBe(false);
    expect(unlocked.vault.payload).toEqual(created.payload);

    const wrong = await unlockVault(harness.deps, 'wrong password');
    expectError(wrong, 'DECRYPT_FAILED');
    expect(harness.storage.writes.length).toBe(writesBefore);
    const again = await unlockVault(harness.deps, 'wrong password');
    expectError(again, 'DECRYPT_FAILED');
  });

  it('recovers and promotes a pending-only record', async () => {
    const harness = makeHarness();
    await create(harness);
    harness.storage.data.set(TEST_KEYS.pending, harness.storage.data.get(TEST_KEYS.record));
    harness.storage.data.delete(TEST_KEYS.record);

    expect(await loadVault(harness.deps)).toMatchObject({ kind: 'LOCKED', pendingOnly: true });
    const unlocked = await unlock(harness);
    expect(unlocked.recoveredFromPending).toBe(true);
    expect(harness.storage.data.has(TEST_KEYS.record)).toBe(true);
    expect(harness.storage.data.has(TEST_KEYS.pending)).toBe(false);
    await expect(unlockVault(harness.deps, 'wrong password')).resolves.toMatchObject({ ok: false });
  });

  it('recovers when the primary record is corrupt but pending is valid', async () => {
    const harness = makeHarness();
    await create(harness);
    harness.storage.data.set(TEST_KEYS.pending, harness.storage.data.get(TEST_KEYS.record));
    harness.storage.data.set(TEST_KEYS.record, { corrupt: true });

    expect(await loadVault(harness.deps)).toMatchObject({
      kind: 'LOCKED',
      pendingOnly: true,
      primaryCorrupt: true,
    });
    const unlocked = await unlock(harness);
    expect(unlocked.recoveredFromPending).toBe(true);
    expect((await loadVault(harness.deps)).kind).toBe('LOCKED');
  });

  it('treats a corrupt pending-only record as locked and reset-only', async () => {
    const harness = makeHarness();
    harness.storage.data.set(TEST_KEYS.pending, { corrupt: true });
    expect(await loadVault(harness.deps)).toEqual({ kind: 'CORRUPT', pendingOnly: true });
    expectError(
      await createVault(harness.deps, { password: PASSWORD, account: mnemonicAccount() }),
      'VAULT_EXISTS',
    );
    expect((await resetVault(harness.deps)).ok).toBe(true);
    expect(await loadVault(harness.deps)).toEqual({ kind: 'NO_VAULT' });
  });

  it('never returns plaintext for a corrupt payload', async () => {
    const harness = makeHarness();
    await create(harness);
    // Replace the ciphertext with a well-formed but wrong ciphertext.
    const record = recordOf(harness);
    const cipher = record['cipher'] as { alg: string; iv: string; ciphertext: string };
    harness.storage.data.set(TEST_KEYS.record, {
      ...record,
      cipher: { ...cipher, ciphertext: bytesToBase64(new Uint8Array(48).fill(2)) },
    });
    expectError(await unlockVault(harness.deps, PASSWORD), 'DECRYPT_FAILED');
  });
});

describe('multi-account operations', () => {
  it('adds accounts without re-deriving the vault key and keeps them after a password change', async () => {
    const harness = makeHarness();
    const first = await create(harness);
    const added = await addAccount(harness.deps, first, {
      source: 'private-key',
      secret: { kind: 'privateKey', hex: KEY_B },
      label: 'Hardhat',
    });
    if (!added.ok) throw added.error;
    expect(added.value.payload.accounts).toHaveLength(2);
    expect(added.value.payload.accounts[1]).toMatchObject({ address: ADDRESS_B, label: 'Hardhat' });

    const unlocked = await unlock(harness);
    expect(unlocked.vault.payload.accounts).toHaveLength(2);

    harness.clock.value += 5000;
    const changed = await changePassword(harness.deps, {
      currentPassword: PASSWORD,
      newPassword: 'a brand new password',
      expectedRecordHash: unlocked.vault.recordHash,
    });
    if (!changed.ok) throw changed.error;
    expect(changed.value.payload.accounts).toHaveLength(2);
    expect(changed.value.createdAt).toBe(first.createdAt);

    expectError(await unlockVault(harness.deps, PASSWORD), 'DECRYPT_FAILED');
    const reUnlocked = await unlock(harness, 'a brand new password');
    expect(reUnlocked.vault.payload.accounts.map((account) => account.address)).toEqual([
      ADDRESS_A,
      ADDRESS_B,
    ]);
    expect(reUnlocked.vault.payload.accounts.map((account) => account.source)).toEqual([
      'mnemonic',
      'private-key',
    ]);
  });

  it('rejects a duplicate address regardless of how it was imported', async () => {
    const harness = makeHarness();
    const vault = await create(harness);
    expectError(
      await addAccount(harness.deps, vault, {
        source: 'mnemonic',
        secret: { kind: 'mnemonic', words: MNEMONIC_A },
      }),
      'ACCOUNT_EXISTS',
    );
    expectError(
      await addAccount(harness.deps, vault, {
        source: 'private-key',
        secret: { kind: 'privateKey', hex: KEY_A },
      }),
      'ACCOUNT_EXISTS',
    );
  });

  it(`stops at ${String(MAX_ACCOUNTS)} accounts`, async () => {
    const harness = makeHarness();
    let vault = await create(harness);
    for (let index = 1; index < MAX_ACCOUNTS; index += 1) {
      const hex = `0x${index.toString(16).padStart(64, '0')}`;
      // Skip index values that are not valid scalars (none here: 1..49).
      const result = await addAccount(harness.deps, vault, {
        source: 'private-key',
        secret: { kind: 'privateKey', hex },
      });
      if (!result.ok) throw result.error;
      vault = result.value;
    }
    expect(vault.payload.accounts).toHaveLength(MAX_ACCOUNTS);
    expectError(
      await addAccount(harness.deps, vault, {
        source: 'private-key',
        secret: { kind: 'privateKey', hex: `0x${(MAX_ACCOUNTS + 1).toString(16).padStart(64, '0')}` },
      }),
      'ACCOUNT_LIMIT',
    );
  });

  it('renames with sanitisation and rejects empty or overlong labels', async () => {
    const harness = makeHarness();
    const vault = await create(harness);
    const id = vault.payload.activeAccountId;
    const renamed = await renameAccount(harness.deps, vault, id, '  \u0000Savings​  ');
    if (!renamed.ok) throw renamed.error;
    expect(renamed.value.payload.accounts[0]?.label).toBe('Savings');

    expectError(await renameAccount(harness.deps, renamed.value, id, '   '), 'LABEL_INVALID');
    expectError(
      await renameAccount(harness.deps, renamed.value, id, 'a'.repeat(65)),
      'LABEL_INVALID',
    );
    expectError(await renameAccount(harness.deps, renamed.value, 'f'.repeat(32), 'x'), 'ACCOUNT_NOT_FOUND');
    expect((await unlock(harness)).vault.payload.accounts[0]?.label).toBe('Savings');
  });

  it('switches the active account and falls back when the active one is deleted', async () => {
    const harness = makeHarness();
    const vault = await create(harness);
    const added = await addAccount(harness.deps, vault, {
      source: 'mnemonic',
      secret: { kind: 'mnemonic', words: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about' },
    });
    if (!added.ok) throw added.error;
    const secondId = added.value.payload.accounts[1]?.id ?? '';
    expect(secondId).not.toBe('');

    const switched = await setActiveAccount(harness.deps, added.value, secondId);
    if (!switched.ok) throw switched.error;
    expect(switched.value.payload.activeAccountId).toBe(secondId);

    const deleted = await deleteAccount(harness.deps, switched.value, secondId);
    if (!deleted.ok) throw deleted.error;
    expect(deleted.value.vault).not.toBeNull();
    expect(deleted.value.vault?.payload.accounts).toHaveLength(1);
    expect(deleted.value.vault?.payload.activeAccountId).toBe(
      deleted.value.vault?.payload.accounts[0]?.id,
    );
  });

  it('deleting the last account removes both records and returns NO_VAULT', async () => {
    const harness = makeHarness();
    const vault = await create(harness);
    const result = await deleteAccount(harness.deps, vault, vault.payload.activeAccountId);
    if (!result.ok) throw result.error;
    expect(result.value.vault).toBeNull();
    expect(harness.storage.data.size).toBe(0);
    expect(await loadVault(harness.deps)).toEqual({ kind: 'NO_VAULT' });
  });

  it('reset removes both records regardless of pending state', async () => {
    const harness = makeHarness();
    await create(harness);
    harness.storage.data.set(TEST_KEYS.pending, { anything: true });
    expect((await resetVault(harness.deps)).ok).toBe(true);
    expect(harness.storage.data.size).toBe(0);
    expect(await loadVault(harness.deps)).toEqual({ kind: 'NO_VAULT' });
  });

  it('persists the idle timeout in the encrypted payload', async () => {
    const harness = makeHarness();
    const vault = await create(harness);
    const disabled = await setIdleTimeout(harness.deps, vault, null);
    if (!disabled.ok) throw disabled.error;
    expect((await unlock(harness)).vault.payload.idleTimeoutMs).toBeNull();
    const custom = await setIdleTimeout(harness.deps, disabled.value, 5 * 60_000);
    if (!custom.ok) throw custom.error;
    expect((await unlock(harness)).vault.payload.idleTimeoutMs).toBe(300_000);
    expectError(
      await setIdleTimeout(harness.deps, custom.value, 0),
      'VAULT_CORRUPT',
    );
  });
});

describe('save preconditions', () => {
  it('rejects a stale vault instead of overwriting a newer record', async () => {
    const harness = makeHarness();
    const vault = await create(harness);
    const payload: VaultPayload = { ...vault.payload, idleTimeoutMs: 60_000 };
    const saved = await saveVault(harness.deps, vault, payload);
    if (!saved.ok) throw saved.error;
    expectError(await saveVault(harness.deps, vault, payload), 'CONFLICT');
  });

  it('refuses to save when the record was removed externally', async () => {
    const harness = makeHarness();
    const vault = await create(harness);
    harness.storage.data.delete(TEST_KEYS.record);
    expectError(await saveVault(harness.deps, vault, vault.payload), 'NO_VAULT');
  });
});

describe('change password atomicity', () => {
  it('rotates salt and ciphertext, keeps createdAt, and removes pending', async () => {
    const harness = makeHarness();
    const vault = await create(harness);
    const oldRecord = recordOf(harness);
    const oldSalt = (oldRecord['kdf'] as { salt: string }).salt;
    const oldIv = (oldRecord['cipher'] as { iv: string }).iv;
    harness.clock.value += 60_000;

    const result = await changePassword(harness.deps, {
      currentPassword: PASSWORD,
      newPassword: 'new password 123',
      expectedRecordHash: vault.recordHash,
    });
    if (!result.ok) throw result.error;
    expect(result.pendingCleanupFailed).toBe(false);
    const newRecord = recordOf(harness);
    expect((newRecord['kdf'] as { salt: string }).salt).not.toBe(oldSalt);
    expect((newRecord['cipher'] as { iv: string }).iv).not.toBe(oldIv);
    expect(newRecord['kdf']).toMatchObject({ m: 65536, t: 3, p: 1 });
    expect(newRecord['createdAt']).toBe(vault.createdAt);
    expect(newRecord['updatedAt']).toBe(vault.createdAt + 60_000);
    expect(harness.storage.data.has(TEST_KEYS.pending)).toBe(false);
    expectError(await unlockVault(harness.deps, PASSWORD), 'DECRYPT_FAILED');
    expect((await unlock(harness, 'new password 123')).vault.payload.accounts).toHaveLength(1);
  });

  it('does nothing when the current password is wrong or the hash is stale', async () => {
    const harness = makeHarness();
    const vault = await create(harness);
    const before = harness.storage.dump();
    const writes = harness.storage.writes.length;
    expectError(
      await changePassword(harness.deps, {
        currentPassword: 'not the password',
        newPassword: 'new password 123',
        expectedRecordHash: vault.recordHash,
      }),
      'DECRYPT_FAILED',
    );
    expect(harness.storage.dump()).toBe(before);
    expect(harness.storage.writes.length).toBe(writes);

    expectError(
      await changePassword(harness.deps, {
        currentPassword: PASSWORD,
        newPassword: 'new password 123',
        expectedRecordHash: 'f'.repeat(64),
      }),
      'CONFLICT',
    );
    expect(harness.storage.dump()).toBe(before);
  });

  it('resolves to "old password still valid" when the primary write fails', async () => {
    const storage = new FaultyStorage();
    const harness = makeHarness(storage);
    const vault = await create(harness);
    storage.failNextSet = { key: TEST_KEYS.record, apply: false };

    const result = await changePassword(harness.deps, {
      currentPassword: PASSWORD,
      newPassword: 'new password 123',
      expectedRecordHash: vault.recordHash,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe('STORAGE_FAILED');
      expect(result.resolution).toBe('old-password-still-valid');
    }
    expect(storage.data.has(TEST_KEYS.pending)).toBe(false);
    expect((await unlock(harness, PASSWORD)).vault.payload.accounts).toHaveLength(1);
    expectError(await unlockVault(harness.deps, 'new password 123'), 'DECRYPT_FAILED');
  });

  it('reports success when the primary write applied but threw', async () => {
    const storage = new FaultyStorage();
    const harness = makeHarness(storage);
    const vault = await create(harness);
    storage.failNextSet = { key: TEST_KEYS.record, apply: true };

    const result = await changePassword(harness.deps, {
      currentPassword: PASSWORD,
      newPassword: 'new password 123',
      expectedRecordHash: vault.recordHash,
    });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value.payload.accounts).toHaveLength(1);
    expect(storage.data.has(TEST_KEYS.pending)).toBe(false);
    expect((await unlock(harness, 'new password 123')).vault.payload.accounts).toHaveLength(1);
    expectError(await unlockVault(harness.deps, PASSWORD), 'DECRYPT_FAILED');
  });

  it('abandons the change when a rival write lands before commit', async () => {
    const storage = new FaultyStorage();
    const harness = makeHarness(storage);
    const vault = await create(harness);

    const rivalHarness = makeHarness();
    await create(rivalHarness, 'rival password');
    const rivalRecord = rivalHarness.storage.data.get(TEST_KEYS.record);

    let reads = 0;
    storage.beforeGet = (key) => {
      if (key !== TEST_KEYS.record) return;
      reads += 1;
      if (reads === 2) storage.data.set(TEST_KEYS.record, rivalRecord);
    };
    const result = await changePassword(harness.deps, {
      currentPassword: PASSWORD,
      newPassword: 'new password 123',
      expectedRecordHash: vault.recordHash,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe('CONFLICT');
      expect(result.resolution).toBe('wallet-changed');
    }
    expect(storage.data.get(TEST_KEYS.record)).toBe(rivalRecord);
    expect(storage.data.has(TEST_KEYS.pending)).toBe(false);
    // The rival record remains unlockable with its own password; the old
    // password must not resurrect a deleted record.
    expect((await unlock(rivalHarness, 'rival password')).vault.payload.accounts).toHaveLength(1);
  });

  it('keeps a foreign pending record it did not write', async () => {
    const storage = new FaultyStorage();
    const harness = makeHarness(storage);
    const vault = await create(harness);

    let pendingReads = 0;
    storage.beforeGet = (key) => {
      if (key !== TEST_KEYS.pending) return;
      pendingReads += 1;
      if (pendingReads !== 1) return;
      const original = storage.data.get(TEST_KEYS.pending) as Record<string, unknown>;
      const cipher = original['cipher'] as { alg: string; iv: string; ciphertext: string };
      storage.data.set(TEST_KEYS.pending, {
        ...original,
        cipher: { ...cipher, ciphertext: bytesToBase64(new Uint8Array(48).fill(3)) },
      });
    };
    const result = await changePassword(harness.deps, {
      currentPassword: PASSWORD,
      newPassword: 'new password 123',
      expectedRecordHash: vault.recordHash,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.resolution).toBe('old-password-still-valid');
    expect(storage.data.has(TEST_KEYS.pending)).toBe(true);
    expect((await unlock(harness, PASSWORD)).vault.payload.accounts).toHaveLength(1);
    expect(storage.data.has(TEST_KEYS.pending)).toBe(false);
  });

  it('does not downgrade KDF parameters', async () => {
    const harness = makeHarness();
    const vault = await create(harness);
    expect(vault.kdf).toEqual({ m: 65536, t: 3, p: 1 });
    const result = await changePassword(harness.deps, {
      currentPassword: PASSWORD,
      newPassword: 'a different password',
      expectedRecordHash: vault.recordHash,
    });
    if (!result.ok) throw result.error;
    expect(result.value.kdf).toEqual({ m: 65536, t: 3, p: 1 });
    expect(kdfOf(recordOf(harness))).toEqual({ m: 65536, t: 3, p: 1 });
  });
});

describe('account derivation edge cases', () => {
  it('derives a unique address for each added private key (sanity for the limit test)', () => {
    const addresses = new Set<string>();
    for (let index = 1; index < 10; index += 1) {
      addresses.add(privateKeyToAddress(`0x${index.toString(16).padStart(64, '0')}`));
    }
    expect(addresses.size).toBe(9);
  });
});
