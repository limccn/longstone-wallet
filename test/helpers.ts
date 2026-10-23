/** Shared fakes for the wallet vault tests: no browser, no timers, no disk. */
import { sha256 } from '@noble/hashes/sha256';
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils';
import type { Argon2Runner, KdfParams } from '../src/index.js';
import type { StorageKeys, WalletStorage } from '../src/index.js';

export const TEST_KEYS: StorageKeys = {
  record: 'test.wallet.v1',
  pending: 'test.wallet.v1.pending',
};

/** In-memory `chrome.storage.local` shape (async get/set/remove). */
export class MemoryStorage implements WalletStorage {
  readonly data = new Map<string, unknown>();
  /** Number of writes per key, useful for "nothing was written" assertions. */
  readonly writes: string[] = [];

  async get(key: string): Promise<Record<string, unknown>> {
    return this.data.has(key) ? { [key]: this.data.get(key) } : {};
  }

  async set(items: Record<string, unknown>): Promise<void> {
    for (const [key, value] of Object.entries(items)) {
      this.writes.push(key);
      this.data.set(key, value);
    }
  }

  async remove(key: string): Promise<void> {
    this.writes.push(key);
    this.data.delete(key);
  }

  dump(): string {
    return JSON.stringify([...this.data.entries()]);
  }
}

/** Storage whose `set` can be made to fail once, after optionally applying it. */
export class FaultyStorage extends MemoryStorage {
  failNextSet: { key: string; apply: boolean; error?: string } | null = null;
  failNextRemove: { key: string; error?: string } | null = null;
  /** Runs before a matching set is applied; lets a test interleave a rival write. */
  beforeSet: ((items: Record<string, unknown>) => void) | null = null;
  /** Runs before every read; lets a test simulate a rival write between reads. */
  beforeGet: ((key: string) => void) | null = null;

  override async get(key: string): Promise<Record<string, unknown>> {
    this.beforeGet?.(key);
    return super.get(key);
  }

  override async set(items: Record<string, unknown>): Promise<void> {
    const keys = Object.keys(items);
    const failure = this.failNextSet;
    if (failure !== null && keys.includes(failure.key)) {
      this.failNextSet = null;
      if (failure.apply) for (const key of keys) this.data.set(key, items[key]);
      throw new Error(failure.error ?? 'simulated storage failure');
    }
    this.beforeSet?.(items);
    await super.set(items);
  }

  override async remove(key: string): Promise<void> {
    const failure = this.failNextRemove;
    if (failure !== null && key === failure.key) {
      this.failNextRemove = null;
      throw new Error(failure.error ?? 'simulated remove failure');
    }
    await super.remove(key);
  }
}

/** Deterministic bytes (xorshift32): same seed, same stream, no short period. */
export function counterRng(seed = 0x9e3779b9): (length: number) => Uint8Array {
  let state = seed >>> 0;
  return (length: number) => {
    const out = new Uint8Array(length);
    for (let i = 0; i < length; i += 1) {
      state ^= (state << 13) >>> 0;
      state ^= state >>> 17;
      state ^= (state << 5) >>> 0;
      state >>>= 0;
      out[i] = state & 0xff;
    }
    return out;
  };
}

/**
 * A deliberately non-Argon2 KDF for algorithm-level tests.
 *
 * The real Argon2id golden vector lives in `crypto.test.ts`; vault-flow tests
 * only need a deterministic, cheap, domain-separated function so a suite of
 * dozens of add/unlock/change operations stays fast.
 */
export const fastArgon2: Argon2Runner = async ({
  password,
  salt,
  params,
}: {
  password: Uint8Array;
  salt: Uint8Array;
  params: KdfParams;
}): Promise<Uint8Array> =>
  sha256(
    concatBytes(
      utf8ToBytes('test-kdf'),
      password,
      salt,
      utf8ToBytes(`${String(params.m)}/${String(params.t)}/${String(params.p)}`),
    ),
  );
