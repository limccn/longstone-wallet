/**
 * Password policy (design §4.5, AC-12/AC-13).
 *
 * Length is measured in Unicode codepoints because that is what the user sees:
 * eight emoji are eight characters. The only transformation is NFC, applied
 * identically at creation, unlock and change-password; trimming or collapsing
 * whitespace would make a vault unopenable by the string the user typed.
 */
import { WalletError } from './errors.js';

export const MIN_PASSWORD_CODEPOINTS = 8;
/** Upper bound before hashing: 1024 codepoints is far beyond any real passphrase. */
export const MAX_PASSWORD_CODEPOINTS = 1024;

export function normalizePassword(raw: string): string {
  return raw.normalize('NFC');
}

export function codepointLength(value: string): number {
  return [...value].length;
}

/**
 * Weak-password warning only (AC-13). This list is intentionally small: a
 * warning, not a gate, and not a value the UI reveals character by character.
 */
const COMMON_PASSWORDS: ReadonlySet<string> = new Set([
  'password',
  'password1',
  'password123',
  '12345678',
  '123456789',
  '1234567890',
  'qwertyui',
  'qwerty123',
  'letmein1',
  'changeme',
  'iloveyou',
  'admin123',
  'welcome1',
  'abc12345',
  '11111111',
  '00000000',
]);

export function isCommonPassword(password: string): boolean {
  return COMMON_PASSWORDS.has(normalizePassword(password).toLowerCase());
}

export type PasswordValidation =
  | { ok: true; value: string }
  | { ok: false; code: 'TOO_SHORT' | 'TOO_LONG' | 'CONFIRM_MISMATCH' };

/**
 * Validates a new password and its confirmation. Both inputs are NFC
 * normalized before comparison, so a composed and a decomposed spelling of the
 * same string are accepted as a match.
 */
export function validateNewPassword(password: string, confirmation: string): PasswordValidation {
  const value = normalizePassword(password);
  const confirm = normalizePassword(confirmation);
  const length = codepointLength(value);
  if (length < MIN_PASSWORD_CODEPOINTS) return { ok: false, code: 'TOO_SHORT' };
  if (length > MAX_PASSWORD_CODEPOINTS) return { ok: false, code: 'TOO_LONG' };
  if (confirm !== value) return { ok: false, code: 'CONFIRM_MISMATCH' };
  return { ok: true, value };
}

/** Returns the normalized password or throws a typed error; never logs input. */
export function assertPasswordAllowed(password: string): string {
  const value = normalizePassword(password);
  const length = codepointLength(value);
  if (length < MIN_PASSWORD_CODEPOINTS) throw new WalletError('TOO_SHORT');
  if (length > MAX_PASSWORD_CODEPOINTS) throw new WalletError('TOO_LONG');
  return value;
}

export type PasswordStrengthLevel = 'too-short' | 'weak' | 'fair' | 'good';

export interface PasswordStrength {
  level: PasswordStrengthLevel;
  common: boolean;
}

/** A UI meter; it never gates submission. */
export function passwordStrength(password: string): PasswordStrength {
  const value = normalizePassword(password);
  const length = codepointLength(value);
  const common = isCommonPassword(value);
  if (length < MIN_PASSWORD_CODEPOINTS) return { level: 'too-short', common };
  if (common) return { level: 'weak', common };

  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((pattern) =>
    pattern.test(value),
  ).length;
  const level: PasswordStrengthLevel =
    length >= 16 || (length >= 12 && classes >= 3)
      ? 'good'
      : length >= 10 && classes >= 2
        ? 'fair'
        : classes >= 3
          ? 'fair'
          : 'weak';
  return { level, common };
}
