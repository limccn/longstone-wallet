/**
 * Purity gate for the shared wallet core (design §3.2, DR-03, SR-10/SR-12/SR-21).
 *
 * This package is the one piece of code in MemoryOverEth that touches wallet
 * secrets. It must stay a pure library: no host globals, no network, no
 * logging, no signing, no storage keys of its own, and no dependency beyond
 * the five pinned crypto libraries. A future edit that adds `fetch` to the
 * vault or imports `viem/accounts` fails here before a review has to notice
 * it.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = path.resolve(__dirname, '..');
const SRC = path.join(ROOT, 'src');

/** The complete public implementation surface; `index.ts` re-exports it. */
const REQUIRED_MODULES = [
  'index.ts',
  'errors.ts',
  'crypto.ts',
  'format.ts',
  'accounts.ts',
  'password.ts',
  'vault.ts',
  'lock.ts',
];

/** Runtime dependencies, pinned exactly. Nothing else may be imported. */
const PINNED_DEPENDENCIES: Record<string, string> = {
  '@noble/curves': '1.9.1',
  '@noble/hashes': '1.8.0',
  '@scure/bip32': '1.7.0',
  '@scure/bip39': '1.6.0',
  'hash-wasm': '4.12.0',
};

function walk(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    return entry.isDirectory() ? walk(full) : [full];
  });
}

function stripComments(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
}

function packageJson(): Record<string, unknown> {
  return JSON.parse(readFileSync(path.join(ROOT, 'package.json'), 'utf8')) as Record<string, unknown>;
}

const sources = walk(SRC).filter((file) => /\.ts$/.test(file));

const FORBIDDEN_IN_CORE: Array<{ id: string; pattern: RegExp }> = [
  { id: 'chrome-api', pattern: /(?:^|[^\w$])chrome\s*\./ },
  { id: 'browser-api', pattern: /(?:^|[^\w$])browser\s*\./ },
  { id: 'vs-code-api', pattern: /from\s+['"]vscode['"]/ },
  { id: 'node-builtin', pattern: /from\s+['"]node:|require\s*\(\s*['"]node:/ },
  { id: 'dom-document', pattern: /\bdocument\s*\./ },
  { id: 'dom-window', pattern: /\bwindow\s*\./ },
  { id: 'localStorage', pattern: /\blocalStorage\b/ },
  { id: 'sessionStorage', pattern: /\bsessionStorage\b/ },
  { id: 'indexeddb', pattern: /\bindexedDB\b/ },
  { id: 'fetch', pattern: /\bfetch\s*\(/ },
  { id: 'xhr', pattern: /\bXMLHttpRequest\b/ },
  { id: 'websocket', pattern: /\bWebSocket\b/ },
  { id: 'send-beacon', pattern: /\bsendBeacon\b/ },
  { id: 'event-source', pattern: /\bEventSource\b/ },
  { id: 'console', pattern: /\bconsole\s*\./ },
  { id: 'debugger', pattern: /\bdebugger\b/ },
  { id: 'process-env', pattern: /\bprocess\s*\.\s*env\b/ },
  { id: 'viem', pattern: /from\s+['"]viem(?:\/[^'"]*)?['"]/ },
  { id: 'signing-account', pattern: /\b(?:privateKeyToAccount|mnemonicToAccount)\b/ },
  { id: 'sign-call', pattern: /\.sign(?:Message|Transaction|TypedData)?\s*\(/ },
  { id: 'math-random', pattern: /\bMath\.random\s*\(/ },
  // Hosts own their physical namespaces; the core only knows `wallet.v1`.
  { id: 'host-storage-key', pattern: /longstone-ext\.wallet/ },
  { id: 'inline-signing-rpc', pattern: /\b(?:eth_sendTransaction|eth_signTypedData)\b/ },
];

describe('wallet core stays pure', () => {
  it('contains exactly the expected modules', () => {
    const names = sources.map((file) => path.basename(file)).sort();
    expect(names).toEqual([...REQUIRED_MODULES].sort());
  });

  it('touches no host, network, logging, or signing API', () => {
    expect(sources.length).toBeGreaterThan(0);
    for (const file of sources) {
      const text = stripComments(readFileSync(file, 'utf8'));
      for (const rule of FORBIDDEN_IN_CORE) {
        expect(rule.pattern.test(text), `${path.relative(ROOT, file)}: ${rule.id}`).toBe(false);
      }
    }
  });

  it('imports only relative modules and the five pinned dependencies', () => {
    const allowed = [
      /^\.\.?\//,
      /^@noble\/curves(?:\/secp256k1)?$/,
      /^@noble\/hashes(?:\/(?:sha256|sha3|utils))?$/,
      /^@scure\/bip32$/,
      /^@scure\/bip39(?:\/wordlists\/english)?$/,
      /^hash-wasm$/,
    ];
    for (const file of sources) {
      const text = stripComments(readFileSync(file, 'utf8'));
      const specifiers = [...text.matchAll(/from\s+['"]([^'"]+)['"]/g)].map((match) => match[1]);
      for (const specifier of specifiers) {
        expect(
          allowed.some((pattern) => pattern.test(specifier ?? '')),
          `${path.relative(ROOT, file)} imports ${String(specifier)}`,
        ).toBe(true);
      }
      expect(text, path.relative(ROOT, file)).not.toMatch(/\bimport\s*\(/);
      expect(text, path.relative(ROOT, file)).not.toMatch(/\brequire\s*\(/);
    }
  });

  it('pins the runtime dependencies and ships only ESM plus types', () => {
    const pkg = packageJson();
    expect(pkg['dependencies']).toEqual(PINNED_DEPENDENCIES);
    for (const forbidden of ['viem', 'vscode', '@limccn/longstone-surface', '@limccn/menhir-core']) {
      expect(pkg['dependencies']).not.toHaveProperty(forbidden);
      expect(pkg['devDependencies']).not.toHaveProperty(forbidden);
    }
    expect(pkg['name']).toBe('@limccn/longstone-wallet');
    expect(pkg['version']).toBe('0.1.0');
    expect(pkg['type']).toBe('module');
    expect(pkg['sideEffects']).toBe(false);
    expect(pkg['exports']).toEqual({
      '.': { types: './dist/index.d.ts', import: './dist/index.js' },
    });
    expect(pkg['files']).toEqual(['dist', 'README.md', 'LICENSE']);
    expect(pkg['engines']).toEqual({ node: '>=24' });
    for (const [name, version] of Object.entries(PINNED_DEPENDENCIES)) {
      expect(version, name).toMatch(/^\d+\.\d+\.\d+$/);
    }
  });
});
