/**
 * Phase 0 blocking spike: bundle hash-wasm's Argon2id for the Node extension
 * host and run it under Node 24.
 *
 * The question is packaging, not cryptography: a VSIX ships no `node_modules`,
 * so the wasm must be inlined into the esbuild CJS bundle and no external
 * `.wasm` file may be required at runtime. The parameters below are the real
 * creation defaults from `src/crypto.ts` (65536/3/1, 32-byte output), so the
 * reported time is representative of an unlock.
 *
 * Run from the package root:
 *   pnpm exec esbuild scripts/spike/entry.ts --bundle --platform=node \
 *     --format=cjs --target=node24 --outfile=scripts/spike/dist/spike.cjs
 *   node scripts/spike/dist/spike.cjs
 */
import { statSync, readdirSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { argon2id } from 'hash-wasm';

// The CJS bundle is `node scripts/spike/dist/spike.cjs`; argv[1] is its path,
// so the measurement works without import.meta in the bundled format.
const BUNDLE_DIR = path.dirname(path.resolve(process.argv[1] ?? '.'));

function bundleSize(): string {
  const bytes = statSync(path.join(BUNDLE_DIR, 'spike.cjs')).size;
  return `${String(bytes)} bytes (${(bytes / 1024).toFixed(1)} KiB)`;
}

function siblingFiles(): string[] {
  return readdirSync(BUNDLE_DIR).sort();
}

async function main(): Promise<void> {
  const password = new TextEncoder().encode(
    'longstone/wallet.v1/kdf\0phase-0 hash-wasm spike password',
  );
  const salt = new Uint8Array(16).fill(0x07);

  const started = performance.now();
  const output = await argon2id({
    password,
    salt,
    iterations: 3,
    parallelism: 1,
    memorySize: 65536,
    hashLength: 32,
    outputType: 'binary',
  });
  const elapsedMs = performance.now() - started;

  const hex = [...output].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  process.stdout.write(`node: ${process.version}\n`);
  process.stdout.write(`bundle: ${bundleSize()}\n`);
  process.stdout.write(`dist files: ${siblingFiles().join(', ')}\n`);
  process.stdout.write(`argon2id(65536,3,1) -> ${hex}\n`);
  process.stdout.write(`argon2id(65536,3,1) time: ${elapsedMs.toFixed(1)} ms\n`);
}

main().catch((error: unknown) => {
  process.stderr.write(`spike failed: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
