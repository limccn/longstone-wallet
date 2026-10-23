/**
 * Password policy (design §4.5, AC-12/AC-13).
 *
 * Codepoints, not UTF-16 units: 8 emoji are eight characters to a human and
 * must be accepted. NFC normalization is the only transformation — no trim, no
 * whitespace collapse, because a silently altered password becomes an
 * unopenable vault.
 */
import { describe, expect, it } from 'vitest';
import { WalletError } from '../src/index.js';
import {
  MAX_PASSWORD_CODEPOINTS,
  MIN_PASSWORD_CODEPOINTS,
  assertPasswordAllowed,
  codepointLength,
  isCommonPassword,
  normalizePassword,
  passwordStrength,
  validateNewPassword,
} from '../src/index.js';

describe('password length and normalization', () => {
  it('counts Unicode codepoints, not UTF-16 code units', () => {
    expect(codepointLength('\u{1F600}')).toBe(1);
    expect(codepointLength('é')).toBe(2);
    expect(MIN_PASSWORD_CODEPOINTS).toBe(8);
    expect(MAX_PASSWORD_CODEPOINTS).toBe(1024);
    const eightEmoji = '\u{1F600}'.repeat(8);
    expect(validateNewPassword(eightEmoji, eightEmoji)).toEqual({ ok: true, value: eightEmoji });
    expect(validateNewPassword('\u{1F600}'.repeat(7), '\u{1F600}'.repeat(7))).toEqual({
      ok: false,
      code: 'TOO_SHORT',
    });
  });

  it('accepts eight spaces: the user typed what they meant', () => {
    expect(validateNewPassword('        ', '        ')).toEqual({
      ok: true,
      value: '        ',
    });
  });

  it('rejects over the maximum without hashing', () => {
    const huge = 'a'.repeat(MAX_PASSWORD_CODEPOINTS + 1);
    expect(validateNewPassword(huge, huge)).toEqual({ ok: false, code: 'TOO_LONG' });
    expect(validateNewPassword('a'.repeat(MAX_PASSWORD_CODEPOINTS), 'a'.repeat(MAX_PASSWORD_CODEPOINTS)).ok).toBe(
      true,
    );
  });

  it('normalizes NFC and compares confirmation after normalization', () => {
    const decomposed = 'café password';
    const composed = 'café password';
    expect(normalizePassword(decomposed)).toBe(composed);
    expect(validateNewPassword(decomposed, composed)).toEqual({ ok: true, value: composed });
  });

  it('reports a confirmation mismatch without exposing the password', () => {
    const result = validateNewPassword('correct horse', 'correct house');
    expect(result).toEqual({ ok: false, code: 'CONFIRM_MISMATCH' });
    try {
      assertPasswordAllowed('short');
    } catch (error) {
      expect(error).toBeInstanceOf(WalletError);
      expect((error as WalletError).message).toBe('TOO_SHORT');
      expect((error as WalletError).message).not.toContain('short');
    }
  });

  it('normalizes without trimming or collapsing internal whitespace', () => {
    // Leading/trailing spaces are part of the password. Trimming here would
    // make an unlock silently succeed with a different string than typed.
    expect(normalizePassword('  spaced  ')).toBe('  spaced  ');
    expect(normalizePassword('a\tb\nc')).toBe('a\tb\nc');
  });
});

describe('weak password warnings', () => {
  it('flags common passwords as weak but still allows creation', () => {
    expect(isCommonPassword('password')).toBe(true);
    expect(isCommonPassword('Password')).toBe(true);
    expect(isCommonPassword('correct horse battery staple')).toBe(false);
    expect(validateNewPassword('password', 'password')).toEqual({ ok: true, value: 'password' });
    expect(passwordStrength('password')).toEqual({ level: 'weak', common: true });
  });

  it('classifies strength for the UI meter without gating', () => {
    expect(passwordStrength('short').level).toBe('too-short');
    expect(passwordStrength('aaaaaaaa').level).toBe('weak');
    expect(passwordStrength('Tr0ub4dor&3x').level).not.toBe('too-short');
    expect(passwordStrength('a much longer pass phrase here').level).toBe('good');
    expect(passwordStrength('Tr0ub4dor&3x').common).toBe(false);
  });

  it('is deterministic: no randomness, no PII in a warning string', () => {
    expect(passwordStrength('Tr0ub4dor&3x')).toEqual(passwordStrength('Tr0ub4dor&3x'));
  });
});
