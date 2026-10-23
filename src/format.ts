/**
 * `wallet.v1` format and payload invariants (design §4.4/§5.1, AC-24).
 *
 * Parsing is a hard boundary: a record read back from extension storage or
 * written by another extension page is untrusted. Everything is validated
 * before the KDF sees a salt or an account list reaches the UI. Unknown fields
 * are dropped, never carried into the returned object.
 */
import {
  MAX_CIPHERTEXT_BASE64_CHARS,
  MAX_CIPHERTEXT_BYTES,
  WALLET_KDF_DOMAIN,
  base64ToBytes,
  isSupportedKdfParams,
  utf8,
  type KdfParams,
} from './crypto.js';
import { isEip55Address } from './accounts.js';
import { WalletError } from './errors.js';

export const WALLET_FORMAT = 'longstone.wallet.v1';
export const WALLET_FORMAT_DOMAIN = WALLET_KDF_DOMAIN.slice(0, -1);
export const WALLET_VERSION = 1;
export const MAX_ACCOUNTS = 50;
export const MAX_LABEL_CODEPOINTS = 64;
export const MAX_MNEMONIC_BYTES = 1024;
export const MIN_IDLE_TIMEOUT_MS = 1;
export const MAX_IDLE_TIMEOUT_MS = 24 * 60 * 60_000;
export { MAX_CIPHERTEXT_BYTES };

export type AccountSource = 'created' | 'mnemonic' | 'private-key';

export type VaultSecret =
  | { kind: 'mnemonic'; words: string }
  | { kind: 'privateKey'; hex: string };

export interface VaultAccount {
  id: string;
  address: string;
  source: AccountSource;
  label: string;
  createdAt: number;
  secret: VaultSecret;
}

export interface VaultPayload {
  accounts: VaultAccount[];
  activeAccountId: string;
  /**
   * Stored inside the ciphertext (PRD R6). `null` disables the idle lock;
   * absent means the default applies (records from before this field existed).
   */
  idleTimeoutMs?: number | null;
}

export interface WalletRecord {
  format: string;
  version: 1;
  domain: string;
  kdf: {
    alg: 'argon2id';
    m: number;
    t: number;
    p: number;
    salt: string;
  };
  cipher: {
    alg: 'AES-256-GCM';
    iv: string;
    ciphertext: string;
  };
  createdAt: number;
  updatedAt: number;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function fail(code: 'VAULT_CORRUPT' | 'KDF_PARAMS_UNSUPPORTED'): never {
  throw new WalletError(code);
}

function asFiniteTimestamp(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) fail('VAULT_CORRUPT');
  return value;
}

function asBase64OfLength(value: unknown, length: number): string {
  // Reject by encoded length first: decoding (and re-encoding for
  // canonicality) an oversized attacker-controlled string is the allocation
  // AC-19 forbids. Canonical base64 of `length` bytes has a fixed char count.
  const expectedChars = Math.ceil(length / 3) * 4;
  if (typeof value !== 'string' || value.length !== expectedChars) fail('VAULT_CORRUPT');
  let bytes: Uint8Array;
  try {
    bytes = base64ToBytes(value);
  } catch {
    fail('VAULT_CORRUPT');
  }
  if (bytes.length !== length) fail('VAULT_CORRUPT');
  return value;
}

/** Strict envelope parse. Throws WalletError with a UI-mappable code. */
export function parseWalletRecord(raw: unknown): WalletRecord {
  const record = asRecord(raw);
  if (record === null) fail('VAULT_CORRUPT');
  if (record['format'] !== WALLET_FORMAT) fail('VAULT_CORRUPT');
  if (record['version'] !== WALLET_VERSION) fail('VAULT_CORRUPT');
  if (record['domain'] !== WALLET_FORMAT_DOMAIN) fail('VAULT_CORRUPT');

  const kdf = asRecord(record['kdf']);
  if (kdf === null || kdf['alg'] !== 'argon2id') fail('VAULT_CORRUPT');
  const { m, t, p } = kdf;
  if (typeof m !== 'number' || typeof t !== 'number' || typeof p !== 'number') {
    fail('VAULT_CORRUPT');
  }
  const params: KdfParams = { m, t, p };
  if (!isSupportedKdfParams(params)) fail('KDF_PARAMS_UNSUPPORTED');
  const salt = asBase64OfLength(kdf['salt'], 16);

  const cipher = asRecord(record['cipher']);
  if (cipher === null || cipher['alg'] !== 'AES-256-GCM') fail('VAULT_CORRUPT');
  const iv = asBase64OfLength(cipher['iv'], 12);
  if (typeof cipher['ciphertext'] !== 'string') fail('VAULT_CORRUPT');
  if (
    cipher['ciphertext'].length === 0 ||
    cipher['ciphertext'].length > MAX_CIPHERTEXT_BASE64_CHARS
  ) {
    fail('VAULT_CORRUPT');
  }
  let ciphertextBytes: Uint8Array;
  try {
    ciphertextBytes = base64ToBytes(cipher['ciphertext']);
  } catch {
    fail('VAULT_CORRUPT');
  }
  if (ciphertextBytes.length === 0 || ciphertextBytes.length > MAX_CIPHERTEXT_BYTES) {
    fail('VAULT_CORRUPT');
  }

  return {
    format: WALLET_FORMAT,
    version: WALLET_VERSION,
    domain: WALLET_FORMAT_DOMAIN,
    kdf: { alg: 'argon2id', m: params.m, t: params.t, p: params.p, salt },
    cipher: { alg: 'AES-256-GCM', iv, ciphertext: cipher['ciphertext'] },
    createdAt: asFiniteTimestamp(record['createdAt']),
    updatedAt: asFiniteTimestamp(record['updatedAt']),
  };
}

/**
 * Removes control characters, bidi overrides and zero-width characters, then
 * trims. Length policy is applied by the caller so the UI can distinguish
 * "empty" (fall back to Account N) from "too long" (rejected).
 */
export function sanitizeLabel(raw: string): string {
  return raw
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .replace(/[؜​-‏‪-‮⁠-⁤⁦-⁩﻿]/g, '')
    .trim();
}

/**
 * Deterministic JSON: object keys sorted, so a reordered write hashes the
 * same. Record hashes and the host's self-write guard both compare this
 * spelling, never `JSON.stringify` output whose key order is insertion order.
 */
export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value) ?? 'undefined';
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableStringify(entry)).join(',')}]`;
  }
  const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
    a < b ? -1 : a > b ? 1 : 0,
  );
  return `{${entries
    .map(([key, entry]) => `${JSON.stringify(key)}:${stableStringify(entry)}`)
    .join(',')}}`;
}

function normalizeSource(value: unknown): AccountSource | null {
  return value === 'created' || value === 'mnemonic' || value === 'private-key' ? value : null;
}

function parseSecret(raw: unknown): VaultSecret {
  const secret = asRecord(raw);
  if (secret === null) fail('VAULT_CORRUPT');
  if (secret['kind'] === 'mnemonic') {
    const words = secret['words'];
    if (typeof words !== 'string' || utf8(words).length > MAX_MNEMONIC_BYTES || words === '') {
      fail('VAULT_CORRUPT');
    }
    return { kind: 'mnemonic', words };
  }
  if (secret['kind'] === 'privateKey') {
    const hex = secret['hex'];
    if (typeof hex !== 'string' || !/^0x[0-9a-f]{64}$/.test(hex)) fail('VAULT_CORRUPT');
    return { kind: 'privateKey', hex };
  }
  fail('VAULT_CORRUPT');
}

function sourceMatchesSecret(source: AccountSource, secret: VaultSecret): boolean {
  return secret.kind === 'mnemonic'
    ? source === 'created' || source === 'mnemonic'
    : source === 'private-key';
}

/**
 * Validates the decrypted payload (AC-24). Returns a normalized copy with
 * sanitized labels and the original secret material; duplicate addresses are
 * compared case-insensitively.
 */
export function validateVaultPayload(raw: unknown): VaultPayload {
  const payload = asRecord(raw);
  if (payload === null) fail('VAULT_CORRUPT');
  const rawAccounts = payload['accounts'];
  if (!Array.isArray(rawAccounts) || rawAccounts.length === 0) fail('VAULT_CORRUPT');
  if (rawAccounts.length > MAX_ACCOUNTS) fail('VAULT_CORRUPT');

  const ids = new Set<string>();
  const addresses = new Set<string>();
  const accounts: VaultAccount[] = [];

  for (const [index, entry] of rawAccounts.entries()) {
    const account = asRecord(entry);
    if (account === null) fail('VAULT_CORRUPT');

    const id = account['id'];
    if (typeof id !== 'string' || !/^[0-9a-f]{32}$/.test(id) || ids.has(id)) fail('VAULT_CORRUPT');
    ids.add(id);

    const address = account['address'];
    if (typeof address !== 'string' || !isEip55Address(address)) fail('VAULT_CORRUPT');
    const addressKey = address.toLowerCase();
    if (addresses.has(addressKey)) fail('VAULT_CORRUPT');
    addresses.add(addressKey);

    const source = normalizeSource(account['source']);
    if (source === null) fail('VAULT_CORRUPT');
    const secret = parseSecret(account['secret']);
    if (!sourceMatchesSecret(source, secret)) fail('VAULT_CORRUPT');

    if (typeof account['label'] !== 'string') fail('VAULT_CORRUPT');
    const label = sanitizeLabel(account['label']);
    if ([...label].length > MAX_LABEL_CODEPOINTS) fail('VAULT_CORRUPT');

    accounts.push({
      id,
      address,
      source,
      label: label === '' ? `Account ${String(index + 1)}` : label,
      createdAt: asFiniteTimestamp(account['createdAt']),
      secret,
    });
  }

  const activeAccountId = payload['activeAccountId'];
  if (typeof activeAccountId !== 'string' || !ids.has(activeAccountId)) fail('VAULT_CORRUPT');

  const result: VaultPayload = { accounts, activeAccountId };
  if ('idleTimeoutMs' in payload) {
    const idle = payload['idleTimeoutMs'];
    if (idle === null) {
      result.idleTimeoutMs = null;
    } else if (
      typeof idle === 'number' &&
      Number.isInteger(idle) &&
      idle >= MIN_IDLE_TIMEOUT_MS &&
      idle <= MAX_IDLE_TIMEOUT_MS
    ) {
      result.idleTimeoutMs = idle;
    } else {
      fail('VAULT_CORRUPT');
    }
  }
  return result;
}
