/**
 * Vault lifecycle (design §5, §7, DR-01/DR-05/DR-06/DR-16/DR-19).
 *
 * This module owns every write to the two storage keys. The AES key lives in
 * the returned `UnlockedVault` object, i.e. in side-panel page memory only; it
 * is never serialised, cached, or passed to a worker.
 *
 * Concurrency model: the side panel is the only writer, but another instance
 * (a second window, a devtools edit) can change storage. Every mutation carries
 * the hash of the record it was derived from and refuses to overwrite a newer
 * one. Password change uses `record.pending` as a two-phase commit so a crash
 * at any step is recoverable with either the old or the new password.
 */
import {
  KDF_LADDER,
  SALT_BYTES,
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  deriveVaultKey,
  encryptJson,
  decryptJson,
  kdfParamsOf,
  randomBytes,
  sha256Hex,
  utf8,
  type Argon2Runner,
  type DeriveInput,
  type KdfParams,
} from './crypto.js';
import {
  MAX_ACCOUNTS,
  MAX_LABEL_CODEPOINTS,
  WALLET_FORMAT,
  WALLET_FORMAT_DOMAIN,
  WALLET_VERSION,
  parseWalletRecord,
  sanitizeLabel,
  stableStringify,
  validateVaultPayload,
  type AccountSource,
  type VaultAccount,
  type VaultPayload,
  type VaultSecret,
  type WalletRecord,
} from './format.js';
import {
  deriveAccountFromMnemonic,
  parseMnemonicInput,
  parsePrivateKeyInput,
} from './accounts.js';
import { WalletError, isWalletError, toWalletError, type WalletErrorCode } from './errors.js';
import { assertPasswordAllowed } from './password.js';

export const DEFAULT_IDLE_TIMEOUT_MS = 15 * 60_000;

export interface StorageKeys {
  record: string;
  pending: string;
}

/** The three async operations the vault needs from `chrome.storage.local`. */
export interface WalletStorage {
  get(key: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(key: string): Promise<void>;
}

export interface VaultDeps {
  storage: WalletStorage;
  keys: StorageKeys;
  now?: () => number;
  rng?: (length: number) => Uint8Array;
  /** Test seam for the Argon2id ladder and failure injection. */
  argon2?: Argon2Runner;
}

export type VaultResult<T> = { ok: true; value: T } | { ok: false; error: WalletError };

export interface UnlockedVault {
  payload: VaultPayload;
  /** Non-extractable AES-256-GCM key; page memory only. */
  key: CryptoKey;
  /** SHA-256 of the canonical record this payload was decrypted from. */
  recordHash: string;
  kdf: KdfParams;
  createdAt: number;
  updatedAt: number;
}

export interface UnlockOutcome {
  vault: UnlockedVault;
  recoveredFromPending: boolean;
}

export interface NewAccountInput {
  source: AccountSource;
  secret: VaultSecret;
  label?: string;
}

export type VaultLoad =
  | { kind: 'NO_VAULT' }
  | {
      kind: 'LOCKED';
      recordHash: string;
      kdf: KdfParams;
      createdAt: number;
      updatedAt: number;
      pendingOnly: boolean;
      primaryCorrupt: boolean;
    }
  | { kind: 'CORRUPT'; pendingOnly: boolean };

export type ChangeResolution = 'old-password-still-valid' | 'try-new-password' | 'wallet-changed';

export type ChangePasswordResult =
  | { ok: true; value: UnlockedVault; pendingCleanupFailed: boolean }
  | { ok: false; error: WalletError; resolution: ChangeResolution };

export interface ChangePasswordInput {
  currentPassword: string;
  newPassword: string;
  expectedRecordHash: string;
}

export interface DeleteOutcome {
  /** `null` when the last account was removed and the vault no longer exists. */
  vault: UnlockedVault | null;
}

function ok<T>(value: T): VaultResult<T> {
  return { ok: true, value };
}

function fail(error: WalletError | WalletErrorCode): VaultResult<never> {
  return { ok: false, error: typeof error === 'string' ? new WalletError(error) : error };
}

function nowOf(deps: VaultDeps): number {
  return deps.now?.() ?? Date.now();
}

function rngOf(deps: VaultDeps): (length: number) => Uint8Array {
  return deps.rng ?? randomBytes;
}

function deriveInput(deps: VaultDeps, password: string, salt: Uint8Array, params: KdfParams): DeriveInput {
  return {
    password,
    salt,
    params,
    ...(deps.argon2 === undefined ? {} : { argon2: deps.argon2 }),
  };
}

export function hashRecord(value: unknown): string {
  return sha256Hex(utf8(stableStringify(value)));
}

interface StoredReads {
  recordRaw: unknown;
  pendingRaw: unknown;
}

async function readStored(deps: VaultDeps): Promise<StoredReads> {
  const [record, pending] = await Promise.all([
    deps.storage.get(deps.keys.record),
    deps.storage.get(deps.keys.pending),
  ]);
  return {
    recordRaw: record[deps.keys.record],
    pendingRaw: pending[deps.keys.pending],
  };
}

function parseOrError(raw: unknown): { record: WalletRecord | null; error: WalletError | null } {
  if (raw === undefined) return { record: null, error: null };
  try {
    return { record: parseWalletRecord(raw), error: null };
  } catch (error) {
    return { record: null, error: toWalletError(error) };
  }
}

function parseErrorCode(recordError: WalletError | null, pendingError: WalletError | null): WalletError {
  for (const error of [recordError, pendingError]) {
    if (error?.code === 'KDF_PARAMS_UNSUPPORTED') return error;
  }
  return new WalletError('VAULT_CORRUPT');
}

function vaultFromRecord(record: WalletRecord, key: CryptoKey, payload: VaultPayload): UnlockedVault {
  return {
    payload,
    key,
    recordHash: hashRecord(record),
    kdf: kdfParamsOf(record.kdf),
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
  };
}

async function tryUnlockRecord(
  record: WalletRecord,
  raw: unknown,
  password: string,
  deps: VaultDeps,
): Promise<VaultResult<UnlockedVault>> {
  try {
    const key = await deriveVaultKey(
      deriveInput(deps, password, base64ToBytes(record.kdf.salt), kdfParamsOf(record.kdf)),
    );
    const json = await decryptJson(key, record.cipher.iv, record.cipher.ciphertext);
    const payload = validateVaultPayload(json);
    return ok({ ...vaultFromRecord(record, key, payload), recordHash: hashRecord(raw) });
  } catch (error) {
    return fail(toWalletError(error));
  }
}

async function decryptWithKey(key: CryptoKey, raw: unknown): Promise<VaultPayload | null> {
  try {
    const record = parseWalletRecord(raw);
    const json = await decryptJson(key, record.cipher.iv, record.cipher.ciphertext);
    return validateVaultPayload(json);
  } catch {
    return null;
  }
}

async function removeQuietly(deps: VaultDeps, key: string): Promise<void> {
  try {
    await deps.storage.remove(key);
  } catch {
    // Cleanup is best effort; the primary record is authoritative.
  }
}

async function removeIfMatches(deps: VaultDeps, pendingHash: string): Promise<boolean> {
  try {
    const read = await deps.storage.get(deps.keys.pending);
    const raw = read[deps.keys.pending];
    if (raw === undefined || hashRecord(raw) !== pendingHash) return true;
    await deps.storage.remove(deps.keys.pending);
    return true;
  } catch {
    return false;
  }
}

/** Existence and decryptability of the stored record, without the password. */
export async function loadVault(deps: VaultDeps): Promise<VaultLoad> {
  const { recordRaw, pendingRaw } = await readStored(deps);
  const primary = parseOrError(recordRaw);
  const pending = parseOrError(pendingRaw);

  if (primary.record !== null) {
    return {
      kind: 'LOCKED',
      recordHash: hashRecord(recordRaw),
      kdf: kdfParamsOf(primary.record.kdf),
      createdAt: primary.record.createdAt,
      updatedAt: primary.record.updatedAt,
      pendingOnly: false,
      primaryCorrupt: false,
    };
  }
  if (pending.record !== null) {
    return {
      kind: 'LOCKED',
      recordHash: hashRecord(pendingRaw),
      kdf: kdfParamsOf(pending.record.kdf),
      createdAt: pending.record.createdAt,
      updatedAt: pending.record.updatedAt,
      pendingOnly: true,
      primaryCorrupt: recordRaw !== undefined,
    };
  }
  if (recordRaw === undefined && pendingRaw === undefined) return { kind: 'NO_VAULT' };
  return { kind: 'CORRUPT', pendingOnly: recordRaw === undefined };
}

function buildAccount(
  input: NewAccountInput,
  index: number,
  now: number,
  rng: (length: number) => Uint8Array,
  existingIds: ReadonlySet<string>,
): VaultAccount {
  let address: string;
  let secret: VaultSecret;
  if (input.secret.kind === 'mnemonic') {
    if (input.source !== 'mnemonic' && input.source !== 'created') {
      throw new WalletError('VAULT_CORRUPT');
    }
    const parsed = parseMnemonicInput(input.secret.words);
    if (!parsed.ok) throw parsed.error;
    address = deriveAccountFromMnemonic(parsed.words).address;
    secret = { kind: 'mnemonic', words: parsed.words };
  } else {
    if (input.source !== 'private-key') throw new WalletError('VAULT_CORRUPT');
    const parsed = parsePrivateKeyInput(input.secret.hex);
    if (!parsed.ok) throw parsed.error;
    address = parsed.address;
    secret = { kind: 'privateKey', hex: parsed.hex };
  }

  const rawLabel = input.label ?? '';
  const label = sanitizeLabel(rawLabel);
  if ([...label].length > MAX_LABEL_CODEPOINTS) throw new WalletError('LABEL_INVALID');

  let id = '';
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const candidate = bytesToHex(rng(16));
    if (!existingIds.has(candidate)) {
      id = candidate;
      break;
    }
  }
  if (id === '') throw new WalletError('VAULT_CORRUPT');

  return {
    id,
    address,
    source: input.source,
    label: label === '' ? `Account ${String(index + 1)}` : label,
    createdAt: now,
    secret,
  };
}

/**
 * Creates the first account and the record. Refuses when either key exists:
 * a lone `pending` record is a recoverable vault, not an empty slot
 * (AC-6/AC-20).
 */
export async function createVault(
  deps: VaultDeps,
  input: { password: string; account: NewAccountInput },
): Promise<VaultResult<UnlockedVault>> {
  try {
    const password = assertPasswordAllowed(input.password);
    const { recordRaw, pendingRaw } = await readStored(deps);
    if (recordRaw !== undefined || pendingRaw !== undefined) return fail('VAULT_EXISTS');

    const now = nowOf(deps);
    const account = buildAccount(input.account, 0, now, rngOf(deps), new Set());
    const payload: VaultPayload = {
      accounts: [account],
      activeAccountId: account.id,
      idleTimeoutMs: DEFAULT_IDLE_TIMEOUT_MS,
    };

    let chosen: { key: CryptoKey; kdf: KdfParams; salt: Uint8Array } | null = null;
    for (const params of KDF_LADDER) {
      const salt = rngOf(deps)(SALT_BYTES);
      try {
        const key = await deriveVaultKey(deriveInput(deps, password, salt, params));
        chosen = { key, kdf: params, salt };
        break;
      } catch (error) {
        if (isWalletError(error) && error.code === 'KDF_UNAVAILABLE') continue;
        return fail(toWalletError(error));
      }
    }
    if (chosen === null) return fail('KDF_UNAVAILABLE');

    const encrypted = await encryptJson(chosen.key, payload);

    // Design §4.5: re-read both keys immediately before the primary write. The
    // entry check above can be stale after the KDF window, so a create that
    // raced another instance must refuse rather than overwrite it. This
    // narrows the race; `chrome.storage.local` has no compare-and-set.
    let recheck: StoredReads;
    try {
      recheck = await readStored(deps);
    } catch {
      return fail('STORAGE_FAILED');
    }
    if (recheck.recordRaw !== undefined || recheck.pendingRaw !== undefined) {
      return fail('VAULT_EXISTS');
    }

    const record: WalletRecord = {
      format: WALLET_FORMAT,
      version: WALLET_VERSION,
      domain: WALLET_FORMAT_DOMAIN,
      kdf: {
        alg: 'argon2id',
        m: chosen.kdf.m,
        t: chosen.kdf.t,
        p: chosen.kdf.p,
        salt: bytesToBase64(chosen.salt),
      },
      cipher: { alg: 'AES-256-GCM', ...encrypted },
      createdAt: now,
      updatedAt: now,
    };
    try {
      await deps.storage.set({ [deps.keys.record]: record });
    } catch (error) {
      return fail(toWalletError(error, 'STORAGE_FAILED'));
    }
    return ok(vaultFromRecord(record, chosen.key, payload));
  } catch (error) {
    return fail(toWalletError(error));
  }
}

/**
 * Unlocks the primary record. On a wrong password with a pending record, tries
 * the pending record and promotes it (the two-phase change landed but the
 * final swap did not).
 */
export async function unlockVault(
  deps: VaultDeps,
  password: string,
): Promise<VaultResult<UnlockOutcome>> {
  try {
    const { recordRaw, pendingRaw } = await readStored(deps);
    const primary = parseOrError(recordRaw);
    const pending = parseOrError(pendingRaw);

    if (primary.record === null && pending.record === null) {
      if (recordRaw === undefined && pendingRaw === undefined) return fail('NO_VAULT');
      return fail(parseErrorCode(primary.error, pending.error));
    }

    if (primary.record !== null) {
      const attempt = await tryUnlockRecord(primary.record, recordRaw, password, deps);
      if (attempt.ok) {
        if (pendingRaw !== undefined) await removeQuietly(deps, deps.keys.pending);
        return ok({ vault: attempt.value, recoveredFromPending: false });
      }
      if (attempt.error.code !== 'DECRYPT_FAILED') return fail(attempt.error);
      if (pending.record !== null) {
        const recovered = await tryUnlockRecord(pending.record, pendingRaw, password, deps);
        if (recovered.ok) {
          try {
            await deps.storage.set({ [deps.keys.record]: pendingRaw });
          } catch {
            return fail('STORAGE_FAILED');
          }
          await removeQuietly(deps, deps.keys.pending);
          return ok({ vault: recovered.value, recoveredFromPending: true });
        }
        if (recovered.error.code !== 'DECRYPT_FAILED') return fail(recovered.error);
      }
      return fail('DECRYPT_FAILED');
    }

    // Primary missing or corrupt; a valid pending record is the only path in.
    if (pending.record !== null) {
      const recovered = await tryUnlockRecord(pending.record, pendingRaw, password, deps);
      if (!recovered.ok) return fail(recovered.error);
      try {
        await deps.storage.set({ [deps.keys.record]: pendingRaw });
      } catch {
        return fail('STORAGE_FAILED');
      }
      await removeQuietly(deps, deps.keys.pending);
      return ok({ vault: recovered.value, recoveredFromPending: true });
    }
    return fail(parseErrorCode(primary.error, pending.error));
  } catch (error) {
    return fail(toWalletError(error));
  }
}

/**
 * Re-encrypts a payload with the in-memory key and writes it, provided the
 * stored record still hashes to the value this vault was unlocked from.
 */
export async function saveVault(
  deps: VaultDeps,
  vault: UnlockedVault,
  payload: VaultPayload,
): Promise<VaultResult<UnlockedVault>> {
  try {
    const validated = validateVaultPayload(payload);
    const current = await deps.storage.get(deps.keys.record);
    const raw = current[deps.keys.record];
    if (raw === undefined) return fail('NO_VAULT');
    if (hashRecord(raw) !== vault.recordHash) return fail('CONFLICT');

    const parsed = parseWalletRecord(raw);
    const now = nowOf(deps);
    const encrypted = await encryptJson(vault.key, validated);
    const record: WalletRecord = {
      ...parsed,
      cipher: { alg: 'AES-256-GCM', ...encrypted },
      updatedAt: now,
    };
    try {
      await deps.storage.set({ [deps.keys.record]: record });
    } catch {
      return fail('STORAGE_FAILED');
    }
    return ok({ ...vault, payload: validated, recordHash: hashRecord(record), updatedAt: now });
  } catch (error) {
    return fail(toWalletError(error));
  }
}

export async function addAccount(
  deps: VaultDeps,
  vault: UnlockedVault,
  input: NewAccountInput,
): Promise<VaultResult<UnlockedVault>> {
  try {
    if (vault.payload.accounts.length >= MAX_ACCOUNTS) return fail('ACCOUNT_LIMIT');
    const account = buildAccount(
      input,
      vault.payload.accounts.length,
      nowOf(deps),
      rngOf(deps),
      new Set(vault.payload.accounts.map((item) => item.id)),
    );
    const address = account.address.toLowerCase();
    if (vault.payload.accounts.some((item) => item.address.toLowerCase() === address)) {
      return fail('ACCOUNT_EXISTS');
    }
    return saveVault(deps, vault, {
      ...vault.payload,
      accounts: [...vault.payload.accounts, account],
    });
  } catch (error) {
    return fail(toWalletError(error));
  }
}

export async function renameAccount(
  deps: VaultDeps,
  vault: UnlockedVault,
  accountId: string,
  rawLabel: string,
): Promise<VaultResult<UnlockedVault>> {
  const label = sanitizeLabel(rawLabel);
  if (label === '' || [...label].length > MAX_LABEL_CODEPOINTS) return fail('LABEL_INVALID');
  if (!vault.payload.accounts.some((account) => account.id === accountId)) {
    return fail('ACCOUNT_NOT_FOUND');
  }
  return saveVault(deps, vault, {
    ...vault.payload,
    accounts: vault.payload.accounts.map((account) =>
      account.id === accountId ? { ...account, label } : account,
    ),
  });
}

export async function setActiveAccount(
  deps: VaultDeps,
  vault: UnlockedVault,
  accountId: string,
): Promise<VaultResult<UnlockedVault>> {
  if (!vault.payload.accounts.some((account) => account.id === accountId)) {
    return fail('ACCOUNT_NOT_FOUND');
  }
  return saveVault(deps, vault, { ...vault.payload, activeAccountId: accountId });
}

/**
 * Stores the idle threshold encrypted with the payload (PRD R6). Invalid values
 * surface as VAULT_CORRUPT from the payload validator.
 */
export async function setIdleTimeout(
  deps: VaultDeps,
  vault: UnlockedVault,
  idleTimeoutMs: number | null,
): Promise<VaultResult<UnlockedVault>> {
  return saveVault(deps, vault, { ...vault.payload, idleTimeoutMs });
}

/**
 * Deletes an account. Removing the last one deletes the vault entirely: an
 * empty-account record is never written (DR-06).
 */
export async function deleteAccount(
  deps: VaultDeps,
  vault: UnlockedVault,
  accountId: string,
): Promise<VaultResult<DeleteOutcome>> {
  const index = vault.payload.accounts.findIndex((account) => account.id === accountId);
  if (index < 0) return fail('ACCOUNT_NOT_FOUND');

  const remaining = vault.payload.accounts.filter((account) => account.id !== accountId);
  if (remaining.length === 0) {
    try {
      const current = await deps.storage.get(deps.keys.record);
      const raw = current[deps.keys.record];
      if (raw === undefined) return fail('NO_VAULT');
      if (hashRecord(raw) !== vault.recordHash) return fail('CONFLICT');
      let failed = false;
      for (const key of [deps.keys.record, deps.keys.pending]) {
        try {
          await deps.storage.remove(key);
        } catch {
          failed = true;
        }
      }
      if (failed) return fail('STORAGE_FAILED');
      return ok({ vault: null });
    } catch (error) {
      return fail(toWalletError(error, 'STORAGE_FAILED'));
    }
  }

  const activeAccountId = remaining.some(
    (account) => account.id === vault.payload.activeAccountId,
  )
    ? vault.payload.activeAccountId
    : (remaining[0]?.id ?? vault.payload.activeAccountId);
  const saved = await saveVault(deps, vault, {
    ...vault.payload,
    accounts: remaining,
    activeAccountId,
  });
  return saved.ok ? ok({ vault: saved.value }) : saved;
}

/** Explicit reset: removes both records regardless of their state. */
export async function resetVault(deps: VaultDeps): Promise<VaultResult<null>> {
  let failed = false;
  for (const key of [deps.keys.pending, deps.keys.record]) {
    try {
      await deps.storage.remove(key);
    } catch {
      failed = true;
    }
  }
  return failed ? fail('STORAGE_FAILED') : ok(null);
}

function changeFailure(
  error: WalletError | WalletErrorCode,
  resolution: ChangeResolution,
): ChangePasswordResult {
  return { ok: false, error: typeof error === 'string' ? new WalletError(error) : error, resolution };
}

interface ChangeFailureContext {
  oldKey: CryptoKey;
  newKey: CryptoKey;
  pendingHash: string;
  fallback: WalletError;
}

/**
 * Decides what state the two-phase change is in. Never guesses: it decrypts
 * the current primary record with both keys and checks the pending record.
 */
async function resolveChangeFailure(
  deps: VaultDeps,
  context: ChangeFailureContext,
): Promise<ChangePasswordResult> {
  let primaryRaw: unknown;
  let primaryPresent = false;
  try {
    const current = await deps.storage.get(deps.keys.record);
    primaryRaw = current[deps.keys.record];
    primaryPresent = primaryRaw !== undefined;
  } catch {
    primaryPresent = false;
  }

  if (primaryPresent) {
    const withNew = await decryptWithKey(context.newKey, primaryRaw);
    if (withNew !== null) {
      try {
        const record = parseWalletRecord(primaryRaw);
        const cleanupOk = await removeIfMatches(deps, context.pendingHash);
        return {
          ok: true,
          value: {
            payload: withNew,
            key: context.newKey,
            recordHash: hashRecord(primaryRaw),
            kdf: kdfParamsOf(record.kdf),
            createdAt: record.createdAt,
            updatedAt: record.updatedAt,
          },
          pendingCleanupFailed: !cleanupOk,
        };
      } catch {
        // Fall through to the undetermined branch below.
      }
    }
    const withOld = await decryptWithKey(context.oldKey, primaryRaw);
    if (withOld !== null) {
      await removeIfMatches(deps, context.pendingHash);
      return changeFailure(context.fallback, 'old-password-still-valid');
    }
  }

  try {
    const pendingRead = await deps.storage.get(deps.keys.pending);
    const pendingRaw = pendingRead[deps.keys.pending];
    if (pendingRaw !== undefined && (await decryptWithKey(context.newKey, pendingRaw)) !== null) {
      return changeFailure(context.fallback, 'try-new-password');
    }
  } catch {
    // Undetermined is reported as such.
  }
  return changeFailure(new WalletError('VAULT_CORRUPT'), 'try-new-password');
}

/**
 * Two-phase password change.
 *
 *   1. verify the current password and the expected record hash
 *   2. derive a new key with a fresh salt (same params — never downgrades)
 *   3. write `record.pending`, read it back and decrypt it
 *   4. re-read the primary record; abort if a rival write landed
 *   5. swap the primary record, then remove `pending`
 *
 * A failure at 3–5 is resolved by inspecting which password opens the primary
 * record, so the UI can tell the user exactly which password is active.
 */
export async function changePassword(
  deps: VaultDeps,
  input: ChangePasswordInput,
): Promise<ChangePasswordResult> {
  try {
    const current = await deps.storage.get(deps.keys.record);
    const baseRaw = current[deps.keys.record];
    if (baseRaw === undefined) return changeFailure('NO_VAULT', 'wallet-changed');

    let base: WalletRecord;
    try {
      base = parseWalletRecord(baseRaw);
    } catch (error) {
      return changeFailure(toWalletError(error), 'wallet-changed');
    }
    const baseHash = hashRecord(baseRaw);
    if (baseHash !== input.expectedRecordHash) {
      return changeFailure('CONFLICT', 'wallet-changed');
    }

    let newPassword: string;
    try {
      newPassword = assertPasswordAllowed(input.newPassword);
    } catch (error) {
      return changeFailure(toWalletError(error), 'old-password-still-valid');
    }

    const params = kdfParamsOf(base.kdf);
    let oldKey: CryptoKey;
    try {
      oldKey = await deriveVaultKey(
        deriveInput(deps, input.currentPassword, base64ToBytes(base.kdf.salt), params),
      );
    } catch (error) {
      return changeFailure(toWalletError(error), 'old-password-still-valid');
    }

    let payload: VaultPayload;
    try {
      const json = await decryptJson(oldKey, base.cipher.iv, base.cipher.ciphertext);
      payload = validateVaultPayload(json);
    } catch (error) {
      return changeFailure(toWalletError(error), 'old-password-still-valid');
    }

    const salt = rngOf(deps)(SALT_BYTES);
    let newKey: CryptoKey;
    try {
      newKey = await deriveVaultKey(deriveInput(deps, newPassword, salt, params));
    } catch (error) {
      return changeFailure(toWalletError(error), 'old-password-still-valid');
    }

    const now = nowOf(deps);
    const encrypted = await encryptJson(newKey, payload);
    const newRecord: WalletRecord = {
      format: WALLET_FORMAT,
      version: WALLET_VERSION,
      domain: WALLET_FORMAT_DOMAIN,
      kdf: {
        alg: 'argon2id',
        m: params.m,
        t: params.t,
        p: params.p,
        salt: bytesToBase64(salt),
      },
      cipher: { alg: 'AES-256-GCM', ...encrypted },
      createdAt: base.createdAt,
      updatedAt: now,
    };
    const pendingHash = hashRecord(newRecord);
    const failureContext: ChangeFailureContext = {
      oldKey,
      newKey,
      pendingHash,
      fallback: new WalletError('STORAGE_FAILED'),
    };

    try {
      await deps.storage.set({ [deps.keys.pending]: newRecord });
    } catch {
      return changeFailure('STORAGE_FAILED', 'old-password-still-valid');
    }

    let verified = false;
    try {
      const readBack = await deps.storage.get(deps.keys.pending);
      const raw = readBack[deps.keys.pending];
      verified = raw !== undefined && hashRecord(raw) === pendingHash && (await decryptWithKey(newKey, raw)) !== null;
    } catch {
      verified = false;
    }
    if (!verified) return resolveChangeFailure(deps, failureContext);

    let currentRaw: unknown;
    try {
      const recheck = await deps.storage.get(deps.keys.record);
      currentRaw = recheck[deps.keys.record];
    } catch {
      return resolveChangeFailure(deps, failureContext);
    }
    if (currentRaw === undefined || hashRecord(currentRaw) !== baseHash) {
      await removeIfMatches(deps, pendingHash);
      return changeFailure('CONFLICT', 'wallet-changed');
    }

    try {
      await deps.storage.set({ [deps.keys.record]: newRecord });
    } catch {
      return resolveChangeFailure(deps, failureContext);
    }

    let pendingCleanupFailed = false;
    try {
      await deps.storage.remove(deps.keys.pending);
    } catch {
      pendingCleanupFailed = true;
    }
    return {
      ok: true,
      value: {
        payload,
        key: newKey,
        recordHash: pendingHash,
        kdf: params,
        createdAt: base.createdAt,
        updatedAt: now,
      },
      pendingCleanupFailed,
    };
  } catch (error) {
    return changeFailure(toWalletError(error), 'old-password-still-valid');
  }
}

export type { AccountSource, VaultAccount, VaultPayload, VaultSecret } from './format.js';
