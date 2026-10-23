/**
 * Account derivation (design §6, AC-9/AC-10).
 *
 * Only audited libraries: @scure/bip39 for the mnemonic, @scure/bip32 for the
 * path, @noble/curves + @noble/hashes for the key and EIP-55 checksum.
 * `viem/accounts` is forbidden (DR-03) so that no signing-capable account
 * object can appear in the bundle.
 */
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';
import { HDKey } from '@scure/bip32';
import { entropyToMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { randomBytes } from './crypto.js';
import { WalletError, type WalletErrorDetails } from './errors.js';

export const DERIVATION_PATH = "m/44'/60'/0'/0/0";
export const MNEMONIC_WORD_COUNT = 12;
/** Import accepts every standard BIP-39 length (PRD R3, design §6.2). */
export const MNEMONIC_WORD_COUNTS: readonly number[] = [12, 15, 18, 21, 24];
export const ENTROPY_BYTES = 16;
export const MAX_MNEMONIC_BYTES = 1024;

const WORDLIST_SET: ReadonlySet<string> = new Set(wordlist);

const SECP256K1_ORDER = BigInt(
  '0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
);

export interface DerivedAccount {
  address: string;
  privateKey: `0x${string}`;
}

/**
 * Generates a 12-word mnemonic from injected 128-bit entropy. The RNG seam
 * exists for tests; production passes `randomBytes` (CSPRNG).
 */
export function generateWalletMnemonic(rng: (length: number) => Uint8Array = randomBytes): string {
  const entropy = rng(ENTROPY_BYTES);
  if (entropy.length !== ENTROPY_BYTES) throw new WalletError('VAULT_CORRUPT');
  return entropyToMnemonic(entropy, wordlist);
}

export type MnemonicInputError =
  | { code: 'MNEMONIC_WORD_COUNT'; wordCount: number }
  | { code: 'MNEMONIC_WORDLIST'; wordIndex: number }
  | { code: 'MNEMONIC_CHECKSUM' };

export type ParsedMnemonic =
  | { ok: true; words: string }
  | { ok: false; error: WalletError };

/**
 * Canonicalises pasted input: NFKD, lowercase, ideographic space to ASCII
 * space, whitespace runs collapsed. BIP-39 phrase comparison itself is on the
 * normalized ASCII wordlist, so this is lossless for valid phrases.
 */
function normalizeWords(raw: string): string[] {
  return raw
    .normalize('NFKD')
    .toLowerCase()
    .replace(/　/g, ' ')
    .split(/\s+/u)
    .filter((word) => word !== '');
}

/** Validation result with non-sensitive details; `null` means valid. */
export function mnemonicInputError(raw: string): MnemonicInputError | null {
  const words = normalizeWords(raw);
  if (!MNEMONIC_WORD_COUNTS.includes(words.length)) {
    return { code: 'MNEMONIC_WORD_COUNT', wordCount: words.length };
  }
  for (const [index, word] of words.entries()) {
    if (!WORDLIST_SET.has(word)) return { code: 'MNEMONIC_WORDLIST', wordIndex: index + 1 };
  }
  if (!validateMnemonic(words.join(' '), wordlist)) return { code: 'MNEMONIC_CHECKSUM' };
  return null;
}

export function parseMnemonicInput(raw: string): ParsedMnemonic {
  const error = mnemonicInputError(raw);
  if (error === null) return { ok: true, words: normalizeWords(raw).join(' ') };
  const details: WalletErrorDetails = {};
  if ('wordCount' in error) details.wordCount = error.wordCount;
  if ('wordIndex' in error) details.wordIndex = error.wordIndex;
  return { ok: false, error: new WalletError(error.code, details) };
}

/** Derives `m/44'/60'/0'/0/0`; throws a typed error for an invalid phrase. */
export function deriveAccountFromMnemonic(words: string): DerivedAccount {
  const parsed = parseMnemonicInput(words);
  if (!parsed.ok) throw parsed.error;
  const seed = mnemonicToSeedSync(parsed.words);
  const child = HDKey.fromMasterSeed(seed).derive(DERIVATION_PATH);
  const privateKeyBytes = child.privateKey;
  if (privateKeyBytes === null || privateKeyBytes.length !== 32) {
    throw new WalletError('VAULT_CORRUPT');
  }
  const privateKey = `0x${bytesToHex(privateKeyBytes)}` as `0x${string}`;
  return { address: privateKeyToAddress(privateKey), privateKey };
}

/** EIP-55 mixed-case checksum, computed from the lowercase hex. */
export function toEip55(address: string): string {
  const lower = address.replace(/^0x/i, '').toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(lower)) throw new WalletError('VAULT_CORRUPT');
  const hash = bytesToHex(keccak_256(utf8ToBytes(lower)));
  let out = '0x';
  for (let index = 0; index < 40; index += 1) {
    const character = lower[index] ?? '';
    const nibble = Number.parseInt(hash[index] ?? '0', 16);
    out += /[a-f]/.test(character) && nibble >= 8 ? character.toUpperCase() : character;
  }
  return out;
}

export function isEip55Address(value: string): boolean {
  if (!/^0x[0-9a-fA-F]{40}$/.test(value)) return false;
  return value === toEip55(value);
}

/** Address for a 32-byte secp256k1 scalar; validates format and range. */
export function privateKeyToAddress(privateKey: string): string {
  const normalized = privateKey.replace(/^0x/i, '');
  if (!/^[0-9a-fA-F]{64}$/.test(normalized)) throw new WalletError('PRIVATE_KEY_FORMAT');
  const scalar = BigInt(`0x${normalized}`);
  if (scalar === BigInt(0) || scalar >= SECP256K1_ORDER) {
    throw new WalletError('PRIVATE_KEY_RANGE');
  }
  const publicKey = secp256k1.getPublicKey(hexToBytes(normalized), false);
  // Uncompressed public key is 0x04 || X || Y; hash the 64-byte X||Y.
  const addressBytes = keccak_256(publicKey.slice(1)).slice(-20);
  return toEip55(`0x${bytesToHex(addressBytes)}`);
}

export type ParsedPrivateKey =
  | { ok: true; hex: `0x${string}`; address: string }
  | { ok: false; error: WalletError };

export function parsePrivateKeyInput(raw: string): ParsedPrivateKey {
  const normalized = raw.trim().replace(/^0x/i, '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(normalized)) {
    return { ok: false, error: new WalletError('PRIVATE_KEY_FORMAT') };
  }
  const scalar = BigInt(`0x${normalized}`);
  if (scalar === BigInt(0) || scalar >= SECP256K1_ORDER) {
    return { ok: false, error: new WalletError('PRIVATE_KEY_RANGE') };
  }
  const hex = `0x${normalized}` as `0x${string}`;
  return { ok: true, hex, address: privateKeyToAddress(hex) };
}
