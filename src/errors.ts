/**
 * Typed wallet errors (design §4.6).
 *
 * `message` is the code itself: error objects can end up in a crash report or
 * a log, and neither the password, a mnemonic word, nor key material may ride
 * along. UI copy lives in the presentation layer, keyed by `code`.
 */
export type WalletErrorCode =
  | 'TOO_SHORT'
  | 'TOO_LONG'
  | 'CONFIRM_MISMATCH'
  | 'DECRYPT_FAILED'
  | 'KDF_UNAVAILABLE'
  | 'KDF_PARAMS_UNSUPPORTED'
  | 'MNEMONIC_WORD_COUNT'
  | 'MNEMONIC_WORDLIST'
  | 'MNEMONIC_CHECKSUM'
  | 'PRIVATE_KEY_FORMAT'
  | 'PRIVATE_KEY_RANGE'
  | 'ACCOUNT_EXISTS'
  | 'ACCOUNT_LIMIT'
  | 'ACCOUNT_NOT_FOUND'
  | 'LABEL_INVALID'
  | 'LOCKED'
  | 'STORAGE_FAILED'
  | 'VAULT_CORRUPT'
  | 'NO_VAULT'
  | 'VAULT_EXISTS'
  | 'CONFLICT';

/**
 * Structured, non-sensitive details. `wordIndex` is 1-based and the word
 * itself is never included.
 */
export interface WalletErrorDetails {
  wordIndex?: number;
  wordCount?: number;
}

export class WalletError extends Error {
  readonly code: WalletErrorCode;
  readonly details: WalletErrorDetails;

  constructor(code: WalletErrorCode, details: WalletErrorDetails = {}) {
    super(code);
    this.name = 'WalletError';
    this.code = code;
    this.details = details;
  }
}

export function isWalletError(error: unknown): error is WalletError {
  return error instanceof WalletError;
}

/** Converts an unknown rejection into a typed error without leaking its text. */
export function toWalletError(error: unknown, fallback: WalletErrorCode = 'VAULT_CORRUPT'): WalletError {
  return isWalletError(error) ? error : new WalletError(fallback);
}
