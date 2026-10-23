/**
 * Crypto contract (design §4.1–§4.4, AC-5/AC-7).
 *
 * The golden vector is the cross-implementation anchor from
 * `research/wallet-vault-crypto-2026-10-22.md`: the same bytes were produced by
 * @noble/hashes and Node's native Argon2id. If hash-wasm ever disagrees, this
 * test fails before a vault is written in a format we cannot unlock.
 */
import { describe, expect, it } from 'vitest';
import type { Argon2Runner, KdfParams } from '../src/index.js';
import {
  MAX_CIPHERTEXT_BYTES,
  WALLET_HKDF_INFO,
  WALLET_KDF_DOMAIN,
  argon2idRunner,
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  decryptJson,
  deriveKdfOutput,
  deriveVaultKey,
  deriveVaultKeyBytes,
  encryptJson,
  hkdfSha256,
  isSupportedKdfParams,
  randomBytes,
  utf8,
} from '../src/index.js';
import { WalletError, isWalletError } from '../src/index.js';
import { normalizePassword } from '../src/index.js';

const GOLDEN_PASSWORD = 'correct horse battery staple';
const GOLDEN_SALT = new Uint8Array(16).fill(0x07);
const GOLDEN_PARAMS: KdfParams = { m: 65536, t: 3, p: 1 };
const FAST_PARAMS: KdfParams = { m: 19456, t: 2, p: 1 };

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

describe('KDF domain and golden vector', () => {
  it('pins the domain tags', () => {
    // Structural guards: a silent edit of either constant would break
    // separation without any other test noticing.
    expect(WALLET_KDF_DOMAIN).toBe('longstone/wallet.v1/kdf\0');
    expect(WALLET_HKDF_INFO).toBe('longstone/wallet.v1/enc');
    expect(WALLET_KDF_DOMAIN.endsWith('\0')).toBe(true);
  });

  it('reproduces the Argon2id + HKDF golden vector', async () => {
    const kdfOut = await deriveKdfOutput({
      password: GOLDEN_PASSWORD,
      salt: GOLDEN_SALT,
      params: GOLDEN_PARAMS,
    });
    expect(bytesToHex(kdfOut)).toBe(
      '55888860fb6666df6ab1e7223573f221d3d42ebe08f407052898a0a95a025302',
    );
    const vaultKey = await deriveVaultKeyBytes({
      password: GOLDEN_PASSWORD,
      salt: GOLDEN_SALT,
      params: GOLDEN_PARAMS,
    });
    expect(bytesToHex(vaultKey)).toBe(
      '0e36bc8472df82ae5b62260c50cf6a02aba0cd7f8469b132afd022ac1da7daf4',
    );
    // Worst-case structural check: even if the M2 content layer reused the
    // exact same Argon2id output, the HKDF label keeps the keys apart.
    const contentKey = await hkdfSha256(kdfOut, 'longstone/content.v1/enc');
    expect(bytesToHex(contentKey)).toBe(
      '6ea49d0f68ff183c410a62e29bff1c1013226e48f123739b4ec964e64d2581b7',
    );
    expect(bytesEqual(vaultKey, contentKey)).toBe(false);
  }, 60_000);

  it('changes the KDF output when the domain tag changes', async () => {
    // Simulates the M2 layer accidentally dropping its own tag: same password,
    // same salt, same params — only the domain prefix differs.
    const contentInput = 'longstone/content.v1/kdf\0' + GOLDEN_PASSWORD;
    const walletOnly = await deriveKdfOutput({
      password: GOLDEN_PASSWORD,
      salt: GOLDEN_SALT,
      params: FAST_PARAMS,
      argon2: argon2idRunner,
    });
    const contentKdfDomain = await deriveKdfOutput({
      password: contentInput,
      salt: GOLDEN_SALT,
      params: FAST_PARAMS,
      argon2: argon2idRunner,
    });
    // `deriveKdfOutput` always prefixes the wallet domain, so this test proves
    // the prefix matters rather than that callers can swap tags: the content
    // tag is part of the password/payload here.
    expect(bytesEqual(walletOnly, contentKdfDomain)).toBe(false);
  }, 60_000);

  it('normalises the password to NFC before the KDF', async () => {
    const composed = 'café password';
    const decomposed = 'café password';
    expect(normalizePassword(decomposed)).toBe(composed);
    const a = await deriveKdfOutput({
      password: composed,
      salt: GOLDEN_SALT,
      params: FAST_PARAMS,
      argon2: argon2idRunner,
    });
    const b = await deriveKdfOutput({
      password: decomposed,
      salt: GOLDEN_SALT,
      params: FAST_PARAMS,
      argon2: argon2idRunner,
    });
    expect(a).toEqual(b);
  }, 60_000);
});

describe('KDF parameter policy', () => {
  it('accepts exactly the three whitelisted parameter sets', () => {
    expect(isSupportedKdfParams({ m: 65536, t: 3, p: 1 })).toBe(true);
    expect(isSupportedKdfParams({ m: 32768, t: 3, p: 1 })).toBe(true);
    expect(isSupportedKdfParams({ m: 19456, t: 2, p: 1 })).toBe(true);
    for (const params of [
      { m: 524288, t: 3, p: 1 },
      { m: 65536, t: 3, p: 2 },
      { m: 65536, t: 3, p: 0 },
      { m: 65536, t: 0, p: 1 },
      { m: 0, t: 3, p: 1 },
      { m: 65536, t: 3, p: 1, extra: true },
      { m: -1, t: 3, p: 1 },
      { m: 65536.5, t: 3, p: 1 },
      {},
      null,
    ]) {
      expect(isSupportedKdfParams(params), JSON.stringify(params)).toBe(false);
    }
  });

  it('refuses an unsupported parameter set without invoking the KDF', async () => {
    let calls = 0;
    const spy: Argon2Runner = async () => {
      calls += 1;
      return new Uint8Array(32);
    };
    await expect(
      deriveKdfOutput({
        password: GOLDEN_PASSWORD,
        salt: GOLDEN_SALT,
        params: { m: 2 ** 20, t: 1, p: 1 },
        argon2: spy,
      }),
    ).rejects.toMatchObject({ code: 'KDF_PARAMS_UNSUPPORTED' });
    expect(calls).toBe(0);
  });

  it('rejects salt lengths other than 16 bytes', async () => {
    for (const length of [0, 12, 15, 17, 32]) {
      await expect(
        deriveKdfOutput({
          password: GOLDEN_PASSWORD,
          salt: new Uint8Array(length),
          params: FAST_PARAMS,
          argon2: async () => new Uint8Array(32),
        }),
      ).rejects.toMatchObject({ code: 'VAULT_CORRUPT' });
    }
  });

  it('reports KDF_UNAVAILABLE when the runner fails or returns wrong length', async () => {
    const failing: Argon2Runner = async () => {
      throw new Error('wasm refused to compile');
    };
    await expect(
      deriveKdfOutput({
        password: GOLDEN_PASSWORD,
        salt: GOLDEN_SALT,
        params: FAST_PARAMS,
        argon2: failing,
      }),
    ).rejects.toMatchObject({ code: 'KDF_UNAVAILABLE' });
    const short: Argon2Runner = async () => new Uint8Array(16);
    await expect(
      deriveKdfOutput({
        password: GOLDEN_PASSWORD,
        salt: GOLDEN_SALT,
        params: FAST_PARAMS,
        argon2: short,
      }),
    ).rejects.toMatchObject({ code: 'KDF_UNAVAILABLE' });
  });
});

describe('AES-256-GCM envelope', () => {
  async function key(password = 'a very secret password'): Promise<CryptoKey> {
    return deriveVaultKey({
      password,
      salt: randomBytes(16),
      params: FAST_PARAMS,
      argon2: async ({ password: pw, salt }) => {
        // Cheap deterministic stand-in; real Argon2id is covered above.
        const out = new Uint8Array(32);
        for (let i = 0; i < pw.length; i += 1) out[i % 32] = (out[i % 32]! ^ pw[i]!) + 1;
        for (let i = 0; i < salt.length; i += 1) out[(i + 7) % 32] = (out[(i + 7) % 32]! ^ salt[i]!) + 1;
        return out;
      },
    });
  }

  it('round-trips structured payloads with a fresh 12-byte IV', async () => {
    const cryptoKey = await key();
    expect(cryptoKey.extractable).toBe(false);
    expect(cryptoKey.algorithm.name).toBe('AES-GCM');
    const value = { accounts: [], note: 'héllo', nested: { n: 42 } };
    const first = await encryptJson(cryptoKey, value);
    const second = await encryptJson(cryptoKey, value);
    expect(base64ToBytes(first.iv).length).toBe(12);
    expect(first.iv).not.toBe(second.iv);
    expect(await decryptJson(cryptoKey, first.iv, first.ciphertext)).toEqual(value);
    expect(await decryptJson(cryptoKey, second.iv, second.ciphertext)).toEqual(value);
  });

  it('fails closed on a wrong key, wrong IV, or tampered ciphertext', async () => {
    const cryptoKey = await key();
    const other = await key('another password');
    const { iv, ciphertext } = await encryptJson(cryptoKey, { secret: 'x' });

    await expect(decryptJson(other, iv, ciphertext)).rejects.toMatchObject({
      code: 'DECRYPT_FAILED',
    });

    const rawCipher = base64ToBytes(ciphertext);
    const tamperedCipher = new Uint8Array(rawCipher);
    tamperedCipher[tamperedCipher.length - 1] =
      (tamperedCipher[tamperedCipher.length - 1] ?? 0) ^ 0x01;
    await expect(
      decryptJson(cryptoKey, iv, bytesToBase64(tamperedCipher)),
    ).rejects.toMatchObject({ code: 'DECRYPT_FAILED' });

    const rawIv = base64ToBytes(iv);
    const tamperedIv = new Uint8Array(rawIv);
    tamperedIv[0] = (tamperedIv[0] ?? 0) ^ 0x01;
    await expect(
      decryptJson(cryptoKey, bytesToBase64(tamperedIv), ciphertext),
    ).rejects.toMatchObject({ code: 'DECRYPT_FAILED' });

    // A wallet ciphertext must not authenticate under a different derived key.
    await expect(decryptJson(other, iv, ciphertext)).rejects.toMatchObject({
      code: 'DECRYPT_FAILED',
    });
  });

  it('rejects oversized ciphertext before touching WebCrypto', async () => {
    const cryptoKey = await key();
    const oversized = bytesToBase64(new Uint8Array(MAX_CIPHERTEXT_BYTES + 1));
    await expect(decryptJson(cryptoKey, bytesToBase64(new Uint8Array(12)), oversized)).rejects.toMatchObject(
      { code: 'VAULT_CORRUPT' },
    );
  });
});

describe('encoding helpers', () => {
  it('round-trips canonical base64 and rejects malformed input', () => {
    const bytes = new Uint8Array([0, 1, 2, 253, 254, 255]);
    const encoded = bytesToBase64(bytes);
    expect(base64ToBytes(encoded)).toEqual(bytes);
    for (const bad of ['', 'A', 'AAA', 'AA===', '!!!!', 'YWJj\n', 'YW Jj']) {
      expect(() => base64ToBytes(bad), bad).toThrow(WalletError);
    }
    // A canonical decoder must reject encodings that would decode to the same
    // bytes but differ as signed strings (e.g. non-zero trailing bits).
    expect(() => base64ToBytes('AA==')).not.toThrow();
    expect(() => base64ToBytes('AB==')).toThrow(WalletError);
  });

  it('encodes utf8 without relying on Buffer', () => {
    expect(Array.from(utf8('é'))).toEqual([0xc3, 0xa9]);
  });

  it('throws typed errors with no plaintext in the message', () => {
    try {
      base64ToBytes('%%%');
    } catch (error) {
      expect(isWalletError(error)).toBe(true);
      expect((error as WalletError).message).toBe('VAULT_CORRUPT');
      expect((error as WalletError).message).not.toContain('correct horse');
    }
  });
});
