/**
 * @limccn/longstone-wallet — the only implementation of the `wallet.v1`
 * record: format, Argon2id + HKDF + AES-256-GCM, BIP-39/BIP-32 derivation,
 * password policy and the vault lifecycle.
 *
 * The package is host-neutral by construction. It never signs, never talks to
 * a network, never reads a host storage API and never logs. Hosts inject
 * storage, clock and randomness through `VaultDeps`, map the logical keys
 * below to their own namespace, and own every UI, session and lock decision.
 */
import type { StorageKeys } from './vault.js';

// ---------------------------------------------------------------------------
// Logical storage keys
// ---------------------------------------------------------------------------
// Hosts keep their own physical mapping (the browser uses `longstone-ext.*`,
// VS Code uses `longstone.*`); these are the keys the core passes to the
// injected storage adapter.

export const RECORD_KEY = 'wallet.v1';
export const PENDING_KEY = 'wallet.v1.pending';

export const DEFAULT_STORAGE_KEYS: StorageKeys = {
  record: RECORD_KEY,
  pending: PENDING_KEY,
};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export { WalletError, isWalletError, toWalletError } from './errors.js';
export type { WalletErrorCode, WalletErrorDetails } from './errors.js';

// ---------------------------------------------------------------------------
// Crypto: KDF, HKDF, AEAD, encodings
// ---------------------------------------------------------------------------

export {
  WALLET_KDF_DOMAIN,
  WALLET_HKDF_INFO,
  SALT_BYTES,
  IV_BYTES,
  KEY_BYTES,
  MAX_CIPHERTEXT_BYTES,
  SALT_BASE64_CHARS,
  IV_BASE64_CHARS,
  MAX_CIPHERTEXT_BASE64_CHARS,
  KDF_LADDER,
  isSupportedKdfParams,
  kdfParamsOf,
  bytesToBase64,
  base64ToBytes,
  bytesToHex,
  utf8,
  sha256Hex,
  randomBytes,
  argon2idRunner,
  deriveKdfOutput,
  hkdfSha256,
  deriveVaultKeyBytes,
  deriveVaultKey,
  encryptJson,
  decryptJson,
} from './crypto.js';
export type {
  Argon2Input,
  Argon2Runner,
  DeriveInput,
  EncryptedJson,
  KdfParams,
} from './crypto.js';

// ---------------------------------------------------------------------------
// Format: envelope and payload invariants
// ---------------------------------------------------------------------------

export {
  WALLET_FORMAT,
  WALLET_FORMAT_DOMAIN,
  WALLET_VERSION,
  MAX_ACCOUNTS,
  MAX_LABEL_CODEPOINTS,
  MAX_MNEMONIC_BYTES,
  MIN_IDLE_TIMEOUT_MS,
  MAX_IDLE_TIMEOUT_MS,
  parseWalletRecord,
  sanitizeLabel,
  stableStringify,
  validateVaultPayload,
} from './format.js';
export type {
  AccountSource,
  VaultAccount,
  VaultPayload,
  VaultSecret,
  WalletRecord,
} from './format.js';

// ---------------------------------------------------------------------------
// Accounts: BIP-39 generation/import, derivation, EIP-55
// ---------------------------------------------------------------------------

export {
  DERIVATION_PATH,
  MNEMONIC_WORD_COUNT,
  MNEMONIC_WORD_COUNTS,
  ENTROPY_BYTES,
  generateWalletMnemonic,
  mnemonicInputError,
  parseMnemonicInput,
  deriveAccountFromMnemonic,
  toEip55,
  isEip55Address,
  privateKeyToAddress,
  parsePrivateKeyInput,
} from './accounts.js';
export type {
  DerivedAccount,
  MnemonicInputError,
  ParsedMnemonic,
  ParsedPrivateKey,
} from './accounts.js';

// ---------------------------------------------------------------------------
// Password policy
// ---------------------------------------------------------------------------

export {
  MIN_PASSWORD_CODEPOINTS,
  MAX_PASSWORD_CODEPOINTS,
  normalizePassword,
  codepointLength,
  isCommonPassword,
  validateNewPassword,
  assertPasswordAllowed,
  passwordStrength,
} from './password.js';
export type {
  PasswordStrength,
  PasswordStrengthLevel,
  PasswordValidation,
} from './password.js';

// ---------------------------------------------------------------------------
// Vault lifecycle
// ---------------------------------------------------------------------------

export {
  DEFAULT_IDLE_TIMEOUT_MS,
  hashRecord,
  loadVault,
  createVault,
  unlockVault,
  saveVault,
  addAccount,
  renameAccount,
  setActiveAccount,
  setIdleTimeout,
  deleteAccount,
  resetVault,
  changePassword,
} from './vault.js';
export type {
  ChangePasswordInput,
  ChangePasswordResult,
  ChangeResolution,
  DeleteOutcome,
  NewAccountInput,
  StorageKeys,
  UnlockOutcome,
  UnlockedVault,
  VaultDeps,
  VaultLoad,
  VaultResult,
  WalletStorage,
} from './vault.js';

// ---------------------------------------------------------------------------
// Lock lifecycle and async epoch gate
// ---------------------------------------------------------------------------

export { createLockController, createEpochGate } from './lock.js';
export type {
  EpochGate,
  LockController,
  LockControllerOptions,
  LockReason,
} from './lock.js';
