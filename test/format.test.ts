/**
 * `wallet.v1` record and payload invariants (design §4.4/§5.1, AC-24).
 *
 * A record can arrive from disk or from malicious code with `storage` access.
 * Parsing is strict: everything is validated before a byte reaches the KDF or
 * an account list reaches a render. Unknown fields are ignored, never merged.
 */
import { describe, expect, it } from 'vitest';
import type { VaultAccount } from '../src/index.js';
import {
  MAX_ACCOUNTS,
  MAX_CIPHERTEXT_BYTES,
  MAX_LABEL_CODEPOINTS,
  WALLET_FORMAT,
  WALLET_FORMAT_DOMAIN,
  parseWalletRecord,
  sanitizeLabel,
  validateVaultPayload,
} from '../src/index.js';
import { bytesToBase64, utf8 } from '../src/index.js';
import { WalletError } from '../src/index.js';
import { isEip55Address } from '../src/index.js';

const ADDRESS_A = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const ADDRESS_B = '0x9858EfFD232B4033E47d90003D41EC34EcaEda94';
const MNEMONIC_A = 'test test test test test test test test test test test junk';
const KEY_A = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const TS = 1_700_000_000_000;

function validRecord(): Record<string, unknown> {
  return {
    format: WALLET_FORMAT,
    version: 1,
    domain: WALLET_FORMAT_DOMAIN,
    kdf: { alg: 'argon2id', m: 19456, t: 2, p: 1, salt: bytesToBase64(new Uint8Array(16).fill(7)) },
    cipher: {
      alg: 'AES-256-GCM',
      iv: bytesToBase64(new Uint8Array(12).fill(1)),
      ciphertext: bytesToBase64(new Uint8Array(32).fill(9)),
    },
    createdAt: TS,
    updatedAt: TS,
  };
}

function kdf(): Record<string, unknown> {
  return validRecord()['kdf'] as Record<string, unknown>;
}

function cipher(): Record<string, unknown> {
  return validRecord()['cipher'] as Record<string, unknown>;
}

function account(overrides: Partial<VaultAccount> = {}): VaultAccount {
  return {
    id: '0123456789abcdef0123456789abcdef',
    address: ADDRESS_A,
    source: 'mnemonic',
    label: 'Account 1',
    createdAt: TS,
    secret: { kind: 'mnemonic', words: MNEMONIC_A },
    ...overrides,
  };
}

function expectCode(fn: () => unknown, code: string): void {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(WalletError);
    expect((error as WalletError).code).toBe(code);
    return;
  }
  throw new Error(`expected ${code}`);
}

describe('record envelope', () => {
  it('accepts the canonical record and ignores unknown fields', () => {
    const parsed = parseWalletRecord({ ...validRecord(), future: { x: 1 } });
    expect(parsed).toEqual(validRecord());
    expect(parsed).not.toHaveProperty('future');
  });

  it('rejects a wrong format tag, version or domain', () => {
    expectCode(() => parseWalletRecord({ ...validRecord(), format: 'longstone.wallet.v2' }), 'VAULT_CORRUPT');
    expectCode(() => parseWalletRecord({ ...validRecord(), version: 2 }), 'VAULT_CORRUPT');
    expectCode(
      () => parseWalletRecord({ ...validRecord(), domain: 'longstone/content.v1/kdf' }),
      'VAULT_CORRUPT',
    );
    expectCode(() => parseWalletRecord(null), 'VAULT_CORRUPT');
    expectCode(() => parseWalletRecord([]), 'VAULT_CORRUPT');
    expectCode(() => parseWalletRecord({ ...validRecord(), kdf: null }), 'VAULT_CORRUPT');
    expectCode(() => parseWalletRecord({ ...validRecord(), cipher: null }), 'VAULT_CORRUPT');
  });

  it('rejects wrong algorithms', () => {
    expectCode(
      () => parseWalletRecord({ ...validRecord(), kdf: { ...kdf(), alg: 'scrypt' } }),
      'VAULT_CORRUPT',
    );
    expectCode(
      () => parseWalletRecord({ ...validRecord(), cipher: { ...cipher(), alg: 'AES-128-GCM' } }),
      'VAULT_CORRUPT',
    );
  });

  it('enforces salt/IV byte lengths and canonical base64', () => {
    expectCode(
      () =>
        parseWalletRecord({
          ...validRecord(),
          kdf: { ...kdf(), salt: bytesToBase64(new Uint8Array(15)) },
        }),
      'VAULT_CORRUPT',
    );
    expectCode(
      () =>
        parseWalletRecord({
          ...validRecord(),
          cipher: { ...cipher(), iv: bytesToBase64(new Uint8Array(11)) },
        }),
      'VAULT_CORRUPT',
    );
    expectCode(
      () =>
        parseWalletRecord({
          ...validRecord(),
          cipher: { ...cipher(), iv: 'AAAAAAAAAAAAAAA!' },
        }),
      'VAULT_CORRUPT',
    );
    expectCode(
      () =>
        parseWalletRecord({
          ...validRecord(),
          cipher: { ...cipher(), ciphertext: 'AB==' },
        }),
      'VAULT_CORRUPT',
    );
  });

  it('rejects a ciphertext whose encoded length exceeds the cap', () => {
    // The parser gates on the base64 *character* count before calling the
    // decoder, so the bound is checked without a transient allocation; this
    // string is one 4-char block over the canonical max.
    expectCode(
      () =>
        parseWalletRecord({
          ...validRecord(),
          cipher: {
            ...cipher(),
            ciphertext: 'A'.repeat(Math.ceil((MAX_CIPHERTEXT_BYTES + 1) / 3) * 4),
          },
        }),
      'VAULT_CORRUPT',
    );
  });

  it('requires whitelisted KDF parameters', () => {
    for (const params of [
      { m: 524288, t: 3, p: 1 },
      { m: 65536, t: 3, p: 4 },
      { m: 65536, t: 2, p: 1 },
    ]) {
      expectCode(
        () => parseWalletRecord({ ...validRecord(), kdf: { ...kdf(), ...params } }),
        'KDF_PARAMS_UNSUPPORTED',
      );
    }
  });

  it('rejects non-finite timestamps', () => {
    for (const bad of [undefined, -1, Number.NaN, Number.POSITIVE_INFINITY, '1700']) {
      expectCode(() => parseWalletRecord({ ...validRecord(), createdAt: bad }), 'VAULT_CORRUPT');
    }
  });
});

describe('payload invariants', () => {
  it('accepts one account and returns a normalised copy', () => {
    const payload = { accounts: [account()], activeAccountId: account().id };
    expect(validateVaultPayload(payload)).toEqual(payload);
    expect(isEip55Address(account().address)).toBe(true);
  });

  it('rejects an empty or oversized account list', () => {
    expectCode(() => validateVaultPayload({ accounts: [], activeAccountId: '' }), 'VAULT_CORRUPT');
    const many = Array.from({ length: MAX_ACCOUNTS + 1 }, (_, index) => {
      const suffix = index.toString(16);
      return account({
        id: index.toString(16).padStart(32, '0'),
        address: `0x${'0'.repeat(40 - suffix.length)}${suffix}`,
        label: `Account ${String(index + 1)}`,
        source: 'private-key',
        secret: { kind: 'privateKey', hex: KEY_A },
      });
    });
    expectCode(
      () => validateVaultPayload({ accounts: many, activeAccountId: many[0]?.id }),
      'VAULT_CORRUPT',
    );
  });

  it('requires a live activeAccountId', () => {
    expectCode(
      () => validateVaultPayload({ accounts: [account()], activeAccountId: 'f'.repeat(32) }),
      'VAULT_CORRUPT',
    );
    expectCode(() => validateVaultPayload({ accounts: [account()] }), 'VAULT_CORRUPT');
  });

  it('rejects duplicate ids and duplicate addresses', () => {
    const second = account({ address: ADDRESS_B, id: 'f'.repeat(32) });
    expectCode(
      () =>
        validateVaultPayload({
          accounts: [account(), { ...second, id: account().id }],
          activeAccountId: account().id,
        }),
      'VAULT_CORRUPT',
    );
    expectCode(
      () =>
        validateVaultPayload({
          accounts: [account(), { ...second, id: 'a'.repeat(32), address: account().address }],
          activeAccountId: account().id,
        }),
      'VAULT_CORRUPT',
    );
    expectCode(
      () =>
        validateVaultPayload({
          accounts: [account({ id: 'Z'.repeat(32) })],
          activeAccountId: 'Z'.repeat(32),
        }),
      'VAULT_CORRUPT',
    );
  });

  it('keeps source and secret kind consistent', () => {
    expectCode(
      () =>
        validateVaultPayload({
          accounts: [{ ...account(), source: 'private-key' }],
          activeAccountId: account().id,
        }),
      'VAULT_CORRUPT',
    );
    expectCode(
      () =>
        validateVaultPayload({
          accounts: [{ ...account(), source: 'mnemonic', secret: { kind: 'privateKey', hex: KEY_A } }],
          activeAccountId: account().id,
        }),
      'VAULT_CORRUPT',
    );
    expectCode(
      () =>
        validateVaultPayload({
          accounts: [{ ...account(), source: 'private-key', secret: { kind: 'mnemonic', words: MNEMONIC_A } }],
          activeAccountId: account().id,
        }),
      'VAULT_CORRUPT',
    );
  });

  it('requires EIP-55 addresses and rejects non-hex or wrong length', () => {
    for (const address of [
      ADDRESS_A.toLowerCase(),
      ADDRESS_A.slice(0, -1),
      '0x' + 'g'.repeat(40),
      'not-an-address',
    ]) {
      expectCode(
        () =>
          validateVaultPayload({
            accounts: [{ ...account(), address }],
            activeAccountId: account().id,
          }),
        'VAULT_CORRUPT',
      );
    }
  });

  it('sanitises labels and rejects overlong ones', () => {
    expect(sanitizeLabel('  hello  ')).toBe('hello');
    expect(sanitizeLabel('\u0000A​B‮C')).toBe('ABC');
    expect(sanitizeLabel('a'.repeat(MAX_LABEL_CODEPOINTS))).toHaveLength(MAX_LABEL_CODEPOINTS);
    const payload = validateVaultPayload({
      accounts: [account({ label: '\u0000A​B' })],
      activeAccountId: account().id,
    });
    expect(payload.accounts[0]?.label).toBe('AB');
    const empty = validateVaultPayload({
      accounts: [account({ label: '​' })],
      activeAccountId: account().id,
    });
    expect(empty.accounts[0]?.label).toBe('Account 1');
    expectCode(
      () =>
        validateVaultPayload({
          accounts: [account({ label: 'a'.repeat(MAX_LABEL_CODEPOINTS + 1) })],
          activeAccountId: account().id,
        }),
      'VAULT_CORRUPT',
    );
  });

  it('bounds and validates secrets', () => {
    expectCode(
      () =>
        validateVaultPayload({
          accounts: [{ ...account(), secret: { kind: 'mnemonic', words: 'a'.repeat(1025) } }],
          activeAccountId: account().id,
        }),
      'VAULT_CORRUPT',
    );
    expectCode(
      () =>
        validateVaultPayload({
          accounts: [
            {
              ...account(),
              source: 'private-key',
              secret: { kind: 'privateKey', hex: KEY_A.toUpperCase().replace('0X', '0x') },
            },
          ],
          activeAccountId: account().id,
        }),
      'VAULT_CORRUPT',
    );
    expectCode(
      () =>
        validateVaultPayload({
          accounts: [{ ...account(), secret: { kind: 'other' } }],
          activeAccountId: account().id,
        }),
      'VAULT_CORRUPT',
    );
  });

  it('accepts only a sane idle timeout and preserves null', () => {
    const base = { accounts: [account()], activeAccountId: account().id };
    expect(validateVaultPayload({ ...base, idleTimeoutMs: null }).idleTimeoutMs).toBeNull();
    expect(validateVaultPayload({ ...base, idleTimeoutMs: 15 * 60_000 }).idleTimeoutMs).toBe(900_000);
    for (const bad of [0, -1, 1.5, 24 * 60 * 60_000 + 1, '900000']) {
      expectCode(() => validateVaultPayload({ ...base, idleTimeoutMs: bad }), 'VAULT_CORRUPT');
    }
  });

  it('does not trust a mnemonic payload word count here (derivation-time concern)', () => {
    // The payload parser bounds bytes but does not re-run BIP-39 validation:
    // the account was validated at creation, and a corrupt payload is caught
    // when it is used. This documents the deliberate boundary.
    expect(utf8(MNEMONIC_A).length).toBeLessThan(1024);
  });
});
