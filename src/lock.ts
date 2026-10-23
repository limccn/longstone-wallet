/**
 * Lock lifecycle (design §7.1, AC-14/AC-15).
 *
 * Pure state with an injected clock: the UI owns `visibilitychange`,
 * `pagehide` and rendering. `check()` is called by the UI's interval; there is
 * no timer here, so a suspended tab cannot "skip" the lock — the next check
 * compares wall-clock timestamps.
 */
export type LockReason = 'explicit' | 'idle' | 'hidden' | 'pagehide' | 'external-change';

export interface LockControllerOptions {
  now: () => number;
  /** Defaults to 15 minutes. */
  timeoutMs?: number;
}

export interface LockController {
  unlock(): void;
  lock(reason: LockReason): boolean;
  touch(): void;
  check(): LockReason | null;
  handleVisibility(visibility: 'visible' | 'hidden'): void;
  setEnabled(enabled: boolean): void;
  setTimeoutMs(ms: number): void;
  isUnlocked(): boolean;
  onLock(listener: (reason: LockReason) => void): () => void;
}

export function createLockController(options: LockControllerOptions): LockController {
  const now = options.now;
  let timeoutMs = options.timeoutMs ?? 15 * 60_000;
  let enabled = true;
  let unlocked = false;
  let lastActivity = 0;
  const listeners = new Set<(reason: LockReason) => void>();

  const lock = (reason: LockReason): boolean => {
    if (!unlocked) return false;
    unlocked = false;
    for (const listener of [...listeners]) listener(reason);
    return true;
  };

  return {
    unlock() {
      unlocked = true;
      lastActivity = now();
    },
    lock,
    touch() {
      if (unlocked) lastActivity = now();
    },
    check() {
      if (!unlocked || !enabled) return null;
      if (now() - lastActivity >= timeoutMs) {
        lock('idle');
        return 'idle';
      }
      return null;
    },
    handleVisibility(visibility) {
      // Hidden always locks, even when the idle timeout is disabled: a side
      // panel that is no longer visible must not keep an AES key in memory.
      if (visibility === 'hidden') lock('hidden');
    },
    setEnabled(value) {
      enabled = value;
    },
    setTimeoutMs(ms) {
      if (!Number.isFinite(ms) || ms <= 0) return;
      timeoutMs = ms;
    },
    isUnlocked() {
      return unlocked;
    },
    onLock(listener) {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
  };
}

export interface EpochGate {
  current(): number;
  bump(): number;
  isCurrent(epoch: number): boolean;
}

/**
 * Discards results of async work started in an older lock session. Every
 * unlock bumps the epoch; a resolve from before the bump must not populate UI
 * state after the vault locked (DR-19).
 */
export function createEpochGate(): EpochGate {
  let epoch = 0;
  return {
    current: () => epoch,
    bump: () => {
      epoch += 1;
      return epoch;
    },
    isCurrent: (value) => value === epoch,
  };
}
