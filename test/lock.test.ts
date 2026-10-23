/**
 * Lock lifecycle (design §7.1, AC-14/AC-15).
 *
 * The controller is pure state plus an injected clock: no timers, no browser
 * events. The UI owns wiring `visibilitychange`/`pagehide` and the epoch gate.
 */
import { describe, expect, it } from 'vitest';
import { createEpochGate, createLockController } from '../src/index.js';

function makeController(timeoutMs = 15 * 60_000) {
  const clock = { value: 1_000 };
  const events: string[] = [];
  const controller = createLockController({ now: () => clock.value, timeoutMs });
  controller.onLock((reason) => events.push(reason));
  return { controller, clock, events };
}

describe('idle timeout', () => {
  it('locks exactly at the threshold, not before', () => {
    const { controller, clock } = makeController();
    controller.unlock();
    expect(controller.isUnlocked()).toBe(true);

    clock.value += 15 * 60_000 - 1;
    expect(controller.check()).toBeNull();
    expect(controller.isUnlocked()).toBe(true);

    clock.value += 1;
    expect(controller.check()).toBe('idle');
    expect(controller.isUnlocked()).toBe(false);
    expect(controller.check()).toBeNull();
  });

  it('touch extends the deadline', () => {
    const { controller, clock } = makeController();
    controller.unlock();
    clock.value += 10 * 60_000;
    controller.touch();
    clock.value += 10 * 60_000;
    expect(controller.check()).toBeNull();
    clock.value += 5 * 60_000;
    expect(controller.check()).toBe('idle');
  });

  it('touch is a no-op while locked and cannot resurrect the vault', () => {
    const { controller, clock } = makeController();
    controller.unlock();
    controller.lock('explicit');
    controller.touch();
    clock.value += 10 ** 9;
    expect(controller.check()).toBeNull();
    expect(controller.isUnlocked()).toBe(false);
  });

  it('can be disabled and re-enabled at runtime', () => {
    const { controller, clock } = makeController();
    controller.unlock();
    controller.setEnabled(false);
    clock.value += 24 * 60 * 60_000;
    expect(controller.check()).toBeNull();
    expect(controller.isUnlocked()).toBe(true);

    controller.setEnabled(true);
    clock.value += 15 * 60_000;
    expect(controller.check()).toBe('idle');
  });
});

describe('explicit and lifecycle locking', () => {
  it('locks on hidden even when the idle timeout is disabled', () => {
    const { controller, events } = makeController();
    controller.unlock();
    controller.setEnabled(false);
    controller.handleVisibility('hidden');
    expect(controller.isUnlocked()).toBe(false);
    expect(events).toEqual(['hidden']);
  });

  it('visible events and hidden while locked are no-ops', () => {
    const { controller, events } = makeController();
    controller.handleVisibility('visible');
    expect(events).toEqual([]);
    controller.unlock();
    controller.handleVisibility('visible');
    expect(controller.isUnlocked()).toBe(true);
    controller.lock('pagehide');
    controller.handleVisibility('hidden');
    expect(events).toEqual(['pagehide']);
  });

  it('is idempotent and notifies once per transition', () => {
    const { controller, events } = makeController();
    controller.unlock();
    expect(controller.lock('explicit')).toBe(true);
    expect(controller.lock('explicit')).toBe(false);
    expect(controller.lock('idle')).toBe(false);
    expect(events).toEqual(['explicit']);
    controller.unlock();
    expect(controller.lock('external-change')).toBe(true);
    expect(events).toEqual(['explicit', 'external-change']);
  });

  it('unsubscribe removes the listener', () => {
    const { controller } = makeController();
    const seen: string[] = [];
    const off = controller.onLock((reason) => seen.push(reason));
    controller.unlock();
    controller.lock('explicit');
    off();
    controller.unlock();
    controller.lock('idle');
    expect(seen).toEqual(['explicit']);
  });

  it('a shorter timeout applies to the next check', () => {
    const { controller, clock } = makeController();
    controller.unlock();
    clock.value += 2000;
    controller.setTimeoutMs(1000);
    expect(controller.check()).toBe('idle');
  });
});

describe('async epoch gate', () => {
  it('discards results from an older epoch', async () => {
    const gate = createEpochGate();
    const first = gate.current();
    gate.bump();
    expect(gate.isCurrent(first)).toBe(false);
    const second = gate.current();
    expect(gate.isCurrent(second)).toBe(true);
    gate.bump();
    expect(gate.isCurrent(second)).toBe(false);
  });
});
