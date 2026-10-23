/**
 * BIP-39 / BIP-32 / EIP-55 (design §6.1–§6.3, AC-9/AC-10).
 *
 * Vectors come from the well-known MetaMask/Hardhat derivations, independently
 * re-derived during research with viem but reproduced here only through
 * @scure + @noble. `viem/accounts` must never appear in the extension, so the
 * address math is exercised by these tests instead of a second library.
 */
import { describe, expect, it } from 'vitest';
import {
  DERIVATION_PATH,
  deriveAccountFromMnemonic,
  generateWalletMnemonic,
  isEip55Address,
  mnemonicInputError,
  parseMnemonicInput,
  parsePrivateKeyInput,
  privateKeyToAddress,
  toEip55,
} from '../src/index.js';
import { counterRng } from './helpers.js';

const VECTOR_A = 'test test test test test test test test test test test junk';
const VECTOR_A_ADDRESS = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const VECTOR_A_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const VECTOR_B = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const VECTOR_B_ADDRESS = '0x9858EfFD232B4033E47d90003D41EC34EcaEda94';
const SECP256K1_N = BigInt(
  '0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
);

describe('mnemonic generation and import', () => {
  it('generates 12 words from 128 bits of injected randomness', () => {
    const mnemonic = generateWalletMnemonic(counterRng());
    expect(mnemonic.split(' ')).toHaveLength(12);
    const parsed = parseMnemonicInput(mnemonic);
    expect(parsed.ok).toBe(true);
  });

  it('derives the two golden accounts', () => {
    expect(DERIVATION_PATH).toBe("m/44'/60'/0'/0/0");
    expect(deriveAccountFromMnemonic(VECTOR_A)).toEqual({
      address: VECTOR_A_ADDRESS,
      privateKey: VECTOR_A_KEY,
    });
    const vectorB = deriveAccountFromMnemonic(VECTOR_B);
    expect(vectorB.address).toBe(VECTOR_B_ADDRESS);
    expect(vectorB.privateKey).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it('accepts uppercase, tabs, newlines and ideographic spaces', () => {
    const messy = `  ${VECTOR_A.toUpperCase().replaceAll(' ', '\t')}\n　 `;
    const parsed = parseMnemonicInput(messy);
    expect(parsed).toEqual({ ok: true, words: VECTOR_A });
    if (parsed.ok) expect(deriveAccountFromMnemonic(parsed.words).address).toBe(VECTOR_A_ADDRESS);
  });

  it('accepts every standard BIP-39 length', () => {
    const fifteen = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon address';
    const twentyFour = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';
    for (const phrase of [fifteen, twentyFour]) {
      const parsed = parseMnemonicInput(phrase);
      expect(parsed.ok).toBe(true);
      if (parsed.ok) {
        const account = deriveAccountFromMnemonic(parsed.words);
        expect(account.address).toMatch(/^0x[0-9a-fA-F]{40}$/);
        expect(account.privateKey).toMatch(/^0x[0-9a-f]{64}$/);
      }
    }
  });

  it('rejects a wrong word count without echoing words', () => {
    const eleven = 'test '.repeat(11).trim();
    expect(mnemonicInputError(eleven)).toEqual({
      code: 'MNEMONIC_WORD_COUNT',
      wordCount: 11,
    });
    expect(parseMnemonicInput(eleven).ok).toBe(false);
    const thirteen = `${VECTOR_A} test`;
    expect(mnemonicInputError(thirteen)).toEqual({
      code: 'MNEMONIC_WORD_COUNT',
      wordCount: 13,
    });
  });

  it('reports the 1-based position of an unknown word, never the word', () => {
    const words = VECTOR_A.split(' ');
    words[11] = 'zzzz';
    const bad = words.join(' ');
    expect(mnemonicInputError(bad)).toEqual({ code: 'MNEMONIC_WORDLIST', wordIndex: 12 });
    const result = parseMnemonicInput(bad);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.message).toBe('MNEMONIC_WORDLIST');
      expect(result.error.message).not.toContain('zzzz');
    }
  });

  it('rejects a bad checksum', () => {
    const badChecksum = 'abandon '.repeat(12).trim();
    expect(mnemonicInputError(badChecksum)).toEqual({ code: 'MNEMONIC_CHECKSUM' });
  });
});

describe('private key import', () => {
  it('derives the Hardhat account 0 address', () => {
    expect(privateKeyToAddress(VECTOR_A_KEY)).toBe(VECTOR_A_ADDRESS);
    const parsed = parsePrivateKeyInput(VECTOR_A_KEY);
    expect(parsed).toEqual({
      ok: true,
      hex: VECTOR_A_KEY,
      address: VECTOR_A_ADDRESS,
    });
  });

  it('accepts uppercase hex and a missing 0x prefix, stores lowercase', () => {
    const upper = VECTOR_A_KEY.slice(2).toUpperCase();
    expect(parsePrivateKeyInput(upper)).toEqual({
      ok: true,
      hex: VECTOR_A_KEY,
      address: VECTOR_A_ADDRESS,
    });
    expect(parsePrivateKeyInput(`0x${upper}`)).toEqual({
      ok: true,
      hex: VECTOR_A_KEY,
      address: VECTOR_A_ADDRESS,
    });
  });

  it('rejects malformed keys without echoing them', () => {
    for (const bad of ['', '0x', '0x1234', 'zz'.repeat(32), `0x${'a'.repeat(63)}`, `0x${'a'.repeat(65)}`]) {
      const result = parsePrivateKeyInput(bad);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.code).toBe('PRIVATE_KEY_FORMAT');
        expect(result.error.message).toBe('PRIVATE_KEY_FORMAT');
        if (bad !== '') expect(result.error.message).not.toContain(bad.slice(0, 8));
      }
    }
  });

  it('enforces the secp256k1 scalar range', () => {
    const zero = `0x${'0'.repeat(64)}`;
    const n = `0x${SECP256K1_N.toString(16)}`;
    const above = `0x${(SECP256K1_N + BigInt(1)).toString(16).padStart(64, '0')}`;
    for (const bad of [zero, n, above]) {
      const result = parsePrivateKeyInput(bad);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.code).toBe('PRIVATE_KEY_RANGE');
    }
    const one = `0x${'0'.repeat(63)}1`;
    expect(parsePrivateKeyInput(one).ok).toBe(true);
    const max = `0x${(SECP256K1_N - BigInt(1)).toString(16).padStart(64, '0')}`;
    expect(parsePrivateKeyInput(max).ok).toBe(true);
  });
});

describe('EIP-55 checksums', () => {
  it('produces and recognises the canonical checksummed address', () => {
    expect(toEip55(VECTOR_A_ADDRESS.toLowerCase())).toBe(VECTOR_A_ADDRESS);
    expect(isEip55Address(VECTOR_A_ADDRESS)).toBe(true);
    expect(isEip55Address(VECTOR_A_ADDRESS.toLowerCase())).toBe(false);
    expect(isEip55Address(VECTOR_A_ADDRESS.toUpperCase().replace('0X', '0x'))).toBe(false);
    expect(isEip55Address('0x1234')).toBe(false);
  });

  it('rejects a single-case-flipped character', () => {
    const flipped = VECTOR_A_ADDRESS.replace('f39F', 'F39F');
    expect(flipped).not.toBe(VECTOR_A_ADDRESS);
    expect(isEip55Address(flipped)).toBe(false);
  });
});
