/**
 * Wallet cryptography (design §4.1–§4.4, v0 crypto review).
 *
 *   kdfInput = UTF8("longstone/wallet.v1/kdf\0" + NFC(password))
 *   kdfOut   = Argon2id(kdfInput, salt, wheitelisted params, 32B)
 *   vaultKey = HKDF-SHA256(kdfOut, salt=empty, info="longstone/wallet.v1/enc")
 *   cipher   = AES-256-GCM(vaultKey, iv=12B CSPRNG)
 *
 * The domain tag inside the KDF preimage is load-bearing: it separates the
 * wallet key from the M2 content key even with identical password, salt and
 * parameters. HKDF labels and different AEAD families are defense in depth.
 */
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex as nobleBytesToHex, utf8ToBytes } from '@noble/hashes/utils';
import { argon2id } from 'hash-wasm';
import { WalletError, isWalletError } from './errors.js';
import { normalizePassword } from './password.js';

export const WALLET_KDF_DOMAIN = 'longstone/wallet.v1/kdf\0';
export const WALLET_HKDF_INFO = 'longstone/wallet.v1/enc';

export const SALT_BYTES = 16;
export const IV_BYTES = 12;
export const KEY_BYTES = 32;
export const MAX_CIPHERTEXT_BYTES = 1024 * 1024;
/** Canonical base64 length for a fixed-size field. */
export const SALT_BASE64_CHARS = Math.ceil(SALT_BYTES / 3) * 4;
export const IV_BASE64_CHARS = Math.ceil(IV_BYTES / 3) * 4;
/**
 * Bound the encoded string *before* decoding it: `base64ToBytes` both decodes
 * and re-encodes for canonicality, so a multi-megabyte hostile record would
 * otherwise force a large transient allocation before the byte cap rejects it.
 */
export const MAX_CIPHERTEXT_BASE64_CHARS = Math.ceil(MAX_CIPHERTEXT_BYTES / 3) * 4;

export interface KdfParams {
  /** Memory cost in KiB. */
  m: number;
  /** Iterations. */
  t: number;
  /** Parallelism. */
  p: number;
}

/**
 * The only parameter sets this version may use. Creation starts at the first
 * and moves down only on KDF_UNAVAILABLE; a record with anything else is
 * refused rather than hashed with attacker-chosen cost (DR-07).
 */
export const KDF_LADDER: readonly KdfParams[] = [
  { m: 65536, t: 3, p: 1 },
  { m: 32768, t: 3, p: 1 },
  { m: 19456, t: 2, p: 1 },
];

export function isSupportedKdfParams(params: unknown): params is KdfParams {
  if (typeof params !== 'object' || params === null || Array.isArray(params)) return false;
  const keys = Object.keys(params);
  if (keys.length !== 3) return false;
  if (!keys.every((key) => key === 'm' || key === 't' || key === 'p')) return false;
  const { m, t, p } = params as Record<string, unknown>;
  return KDF_LADDER.some(
    (candidate) => candidate.m === m && candidate.t === t && candidate.p === p,
  );
}

/** Parameters from an already-validated record, in canonical order. */
export function kdfParamsOf(params: KdfParams): KdfParams {
  return { m: params.m, t: params.t, p: params.p };
}

const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export function bytesToBase64(bytes: Uint8Array): string {
  let out = '';
  for (let index = 0; index < bytes.length; index += 3) {
    const first = bytes[index] ?? 0;
    const second = bytes[index + 1];
    const third = bytes[index + 2];
    out += BASE64_ALPHABET[first >> 2];
    out += BASE64_ALPHABET[((first & 0x03) << 4) | ((second ?? 0) >> 4)];
    out +=
      second === undefined
        ? '='
        : BASE64_ALPHABET[((second & 0x0f) << 2) | ((third ?? 0) >> 6)];
    out += third === undefined ? '=' : BASE64_ALPHABET[third & 0x3f];
  }
  return out;
}

/**
 * Strict, canonical decoder. Re-encoding the decoded bytes must reproduce the
 * input exactly: `AB==` and `AA==` decode to the same byte, so only the
 * canonical spelling is accepted. Non-canonical input would otherwise make two
 * different strings hash to the same record.
 */
export function base64ToBytes(value: string): Uint8Array {
  if (value === '' || !BASE64_PATTERN.test(value)) throw new WalletError('VAULT_CORRUPT');
  const padding = value.endsWith('==') ? 2 : value.endsWith('=') ? 1 : 0;
  const bytes = new Uint8Array((value.length / 4) * 3 - padding);
  let offset = 0;
  for (let index = 0; index < value.length; index += 4) {
    const chunk = value.slice(index, index + 4);
    const a = BASE64_ALPHABET.indexOf(chunk[0] ?? '');
    const b = BASE64_ALPHABET.indexOf(chunk[1] ?? '');
    const c = chunk[2] === '=' ? 0 : BASE64_ALPHABET.indexOf(chunk[2] ?? '');
    const d = chunk[3] === '=' ? 0 : BASE64_ALPHABET.indexOf(chunk[3] ?? '');
    bytes[offset] = (a << 2) | (b >> 4);
    if (offset + 1 < bytes.length) bytes[offset + 1] = ((b & 0x0f) << 4) | (c >> 2);
    if (offset + 2 < bytes.length) bytes[offset + 2] = ((c & 0x03) << 6) | d;
    offset += 3;
  }
  if (bytesToBase64(bytes) !== value) throw new WalletError('VAULT_CORRUPT');
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  return nobleBytesToHex(bytes);
}

export function utf8(value: string): Uint8Array {
  return utf8ToBytes(value);
}

export function sha256Hex(bytes: Uint8Array): string {
  return nobleBytesToHex(sha256(bytes));
}

export function randomBytes(length: number): Uint8Array {
  if (!Number.isInteger(length) || length <= 0 || length > 65536) {
    throw new WalletError('VAULT_CORRUPT');
  }
  const out = new Uint8Array(length);
  globalThis.crypto.getRandomValues(out);
  return out;
}

export interface Argon2Input {
  /** Domain-tagged, NFC-normalized password bytes. */
  password: Uint8Array;
  salt: Uint8Array;
  params: KdfParams;
}

export type Argon2Runner = (input: Argon2Input) => Promise<Uint8Array>;

/** hash-wasm's Argon2id. Any failure becomes KDF_UNAVAILABLE, never a crash. */
export const argon2idRunner: Argon2Runner = async ({ password, salt, params }) => {
  try {
    return await argon2id({
      password,
      salt,
      iterations: params.t,
      parallelism: params.p,
      memorySize: params.m,
      hashLength: KEY_BYTES,
      outputType: 'binary',
    });
  } catch {
    throw new WalletError('KDF_UNAVAILABLE');
  }
};

export interface DeriveInput {
  password: string;
  salt: Uint8Array;
  params: KdfParams;
  argon2?: Argon2Runner;
}

function runnerOf(input: DeriveInput): Argon2Runner {
  return input.argon2 ?? argon2idRunner;
}

/**
 * Runs the domain-tagged KDF once. The password is normalized here, so every
 * caller shares one canonical spelling; length policy belongs to creation.
 */
export async function deriveKdfOutput(input: DeriveInput): Promise<Uint8Array> {
  if (!isSupportedKdfParams(input.params)) throw new WalletError('KDF_PARAMS_UNSUPPORTED');
  if (input.salt.length !== SALT_BYTES) throw new WalletError('VAULT_CORRUPT');
  const passwordBytes = utf8(WALLET_KDF_DOMAIN + normalizePassword(input.password));
  let output: Uint8Array;
  try {
    output = await runnerOf(input)({ password: passwordBytes, salt: input.salt, params: input.params });
  } catch (error) {
    if (isWalletError(error) && error.code === 'KDF_PARAMS_UNSUPPORTED') throw error;
    throw new WalletError('KDF_UNAVAILABLE');
  }
  if (output.length !== KEY_BYTES) throw new WalletError('KDF_UNAVAILABLE');
  return output;
}

function asBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer;
}

/** HKDF-SHA256 with an empty salt (RFC 5869 HashLen zero bytes). */
export async function hkdfSha256(
  ikm: Uint8Array,
  info: string,
  length = KEY_BYTES,
): Promise<Uint8Array> {
  const base = await globalThis.crypto.subtle.importKey(
    'raw',
    asBuffer(ikm),
    'HKDF',
    false,
    ['deriveBits'],
  );
  const bits = await globalThis.crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: asBuffer(utf8(info)) },
    base,
    length * 8,
  );
  return new Uint8Array(bits);
}

export async function deriveVaultKeyBytes(input: DeriveInput): Promise<Uint8Array> {
  const kdfOutput = await deriveKdfOutput(input);
  return hkdfSha256(kdfOutput, WALLET_HKDF_INFO);
}

/** Non-extractable AES-256-GCM key. The raw bytes never leave this function. */
export async function deriveVaultKey(input: DeriveInput): Promise<CryptoKey> {
  const raw = await deriveVaultKeyBytes(input);
  return globalThis.crypto.subtle.importKey(
    'raw',
    asBuffer(raw),
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt'],
  );
}

export interface EncryptedJson {
  iv: string;
  ciphertext: string;
}

export async function encryptJson(key: CryptoKey, value: unknown): Promise<EncryptedJson> {
  const plaintext = utf8(JSON.stringify(value));
  const iv = randomBytes(IV_BYTES);
  const cipher = await globalThis.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: asBuffer(iv), tagLength: 128 },
    key,
    asBuffer(plaintext),
  );
  return { iv: bytesToBase64(iv), ciphertext: bytesToBase64(new Uint8Array(cipher)) };
}

/**
 * Decrypts and parses a payload. Every cryptographic or JSON failure is the
 * same DECRYPT_FAILED: distinguishing "wrong password" from "tampered" would
 * be an oracle, and the UI copy is identical either way.
 */
export async function decryptJson(
  key: CryptoKey,
  ivBase64: string,
  ciphertextBase64: string,
): Promise<unknown> {
  let iv: Uint8Array;
  let ciphertext: Uint8Array;
  // Length gates run on the encoded strings; decode only within the bounds.
  if (ivBase64.length !== IV_BASE64_CHARS) throw new WalletError('DECRYPT_FAILED');
  if (ciphertextBase64.length === 0) throw new WalletError('DECRYPT_FAILED');
  if (ciphertextBase64.length > MAX_CIPHERTEXT_BASE64_CHARS) {
    throw new WalletError('VAULT_CORRUPT');
  }
  try {
    iv = base64ToBytes(ivBase64);
    ciphertext = base64ToBytes(ciphertextBase64);
  } catch {
    throw new WalletError('DECRYPT_FAILED');
  }
  if (iv.length !== IV_BYTES) throw new WalletError('DECRYPT_FAILED');
  if (ciphertext.length === 0) throw new WalletError('DECRYPT_FAILED');
  if (ciphertext.length > MAX_CIPHERTEXT_BYTES) throw new WalletError('VAULT_CORRUPT');
  try {
    const plaintext = await globalThis.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: asBuffer(iv), tagLength: 128 },
      key,
      asBuffer(ciphertext),
    );
    return JSON.parse(new TextDecoder().decode(plaintext)) as unknown;
  } catch {
    throw new WalletError('DECRYPT_FAILED');
  }
}
