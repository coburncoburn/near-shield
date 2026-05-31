#!/usr/bin/env node
// ceremony/scripts/manifest.mjs
// Maintains ceremony/out/manifest.json (or $CEREMONY_OUT/manifest.json).
// Usage:
//   node manifest.mjs init <ptauPath>
//   node manifest.mjs add-contribution <circuit> <name> <zkeySha256>
//   node manifest.mjs set-beacon <circuit> <beaconHex> <source>
//   node manifest.mjs finalize-circuit <circuit> <zkeyPath> <vkJsonPath> <vkBinPath>
//   node manifest.mjs check-circuit <circuit> <vkBinPath>

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { resolve, relative, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const __dirname = dirname(fileURLToPath(import.meta.url));
const ceremonyRoot = resolve(__dirname, '..');
const outDir = process.env.CEREMONY_OUT ?? resolve(ceremonyRoot, 'out');
const manifestPath = resolve(outDir, 'manifest.json');
const POWER = Number(process.env.CEREMONY_POWER ?? 15);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sha256Hex(filePath) {
  const abs = resolve(filePath);
  const bytes = readFileSync(abs);
  return createHash('sha256').update(bytes).digest('hex');
}

function readManifest() {
  if (!existsSync(manifestPath)) {
    throw new Error(`manifest.json not found at ${manifestPath} — run 'init' first`);
  }
  return JSON.parse(readFileSync(manifestPath, 'utf8'));
}

function writeManifest(data) {
  mkdirSync(outDir, { recursive: true });
  writeFileSync(manifestPath, JSON.stringify(data, null, 2) + '\n', 'utf8');
  console.log(`manifest written → ${manifestPath}`);
}

// ---------------------------------------------------------------------------
// Subcommands
// ---------------------------------------------------------------------------

function cmdInit(args) {
  const [ptauPath] = args;
  if (!ptauPath) throw new Error('Usage: init <ptauPath>');
  // I1: Guard against clobbering a populated manifest
  if (existsSync(manifestPath)) {
    const existing = JSON.parse(readFileSync(manifestPath, 'utf8'));
    if (existing.circuits && Object.keys(existing.circuits).length > 0) {
      throw new Error('manifest already has contributions — delete it manually to re-init');
    }
  }
  const abs = resolve(ptauPath);
  const sha256 = sha256Hex(abs);
  // I2: Store a relative path (relative to outDir) so the manifest is portable
  const relPath = relative(outDir, abs);
  const manifest = {
    ptau: { path: relPath, sha256, power: POWER },
    circuits: {},
  };
  writeManifest(manifest);
}

function cmdAddContribution(args) {
  const [circuit, name, zkeySha256] = args;
  if (!circuit || !name || !zkeySha256) {
    throw new Error('Usage: add-contribution <circuit> <name> <zkeySha256>');
  }
  const manifest = readManifest();
  if (!manifest.circuits[circuit]) {
    manifest.circuits[circuit] = { contributions: [] };
  }
  if (!manifest.circuits[circuit].contributions) {
    manifest.circuits[circuit].contributions = [];
  }
  // M4: Guard against duplicate (circuit, name)
  const existing = manifest.circuits[circuit].contributions.find(c => c.name === name);
  if (existing) {
    throw new Error(`contribution name '${name}' already recorded for circuit '${circuit}' — remove it from the manifest to re-record`);
  }
  // M5: Include a timestamp (standard ceremony-transcript practice)
  manifest.circuits[circuit].contributions.push({ name, zkeySha256, timestamp: new Date().toISOString() });
  writeManifest(manifest);
}

function cmdSetBeacon(args) {
  const [circuit, beaconHex, source] = args;
  if (!circuit || !beaconHex || !source) {
    throw new Error('Usage: set-beacon <circuit> <beaconHex> <source>');
  }
  const manifest = readManifest();
  if (!manifest.circuits[circuit]) {
    manifest.circuits[circuit] = { contributions: [] };
  }
  // I3: Guard against silent beacon overwrite
  if (manifest.circuits[circuit].beacon) {
    throw new Error(`beacon already set for '${circuit}' — delete manifest to re-set`);
  }
  manifest.circuits[circuit].beacon = { value: beaconHex, source };
  writeManifest(manifest);
}

function cmdFinalizeCircuit(args) {
  const [circuit, zkeyPath, vkJsonPath, vkBinPath] = args;
  if (!circuit || !zkeyPath || !vkJsonPath || !vkBinPath) {
    throw new Error('Usage: finalize-circuit <circuit> <zkeyPath> <vkJsonPath> <vkBinPath>');
  }
  const manifest = readManifest();
  if (!manifest.circuits[circuit]) {
    manifest.circuits[circuit] = { contributions: [] };
  }
  manifest.circuits[circuit].final = {
    zkeySha256: sha256Hex(zkeyPath),
    vkJsonSha256: sha256Hex(vkJsonPath),
    vkBinSha256: sha256Hex(vkBinPath),
  };
  writeManifest(manifest);
}

function cmdCheckCircuit(args) {
  const [circuit, vkBinPath] = args;
  if (!circuit || !vkBinPath) {
    throw new Error('Usage: check-circuit <circuit> <vkBinPath>');
  }
  const manifest = readManifest();
  const entry = manifest.circuits?.[circuit];
  if (!entry) {
    throw new Error(`circuit '${circuit}' not found in manifest`);
  }
  const expected = entry.final?.vkBinSha256;
  if (!expected) {
    throw new Error(`no final.vkBinSha256 recorded for circuit '${circuit}' — run finalize-circuit first`);
  }
  const actual = sha256Hex(vkBinPath);
  if (actual !== expected) {
    throw new Error(
      `vk.bin sha256 MISMATCH for '${circuit}':\n  expected: ${expected}\n  actual:   ${actual}`
    );
  }
  console.log(`check-circuit OK: ${circuit} vk.bin sha256 matches manifest (${actual})`);
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

const [, , subcommand, ...rest] = process.argv;

const commands = {
  'init': cmdInit,
  'add-contribution': cmdAddContribution,
  'set-beacon': cmdSetBeacon,
  'finalize-circuit': cmdFinalizeCircuit,
  'check-circuit': cmdCheckCircuit,
};

if (!subcommand || !commands[subcommand]) {
  console.error(`Unknown subcommand: ${subcommand ?? '(none)'}`);
  console.error(`Available: ${Object.keys(commands).join(', ')}`);
  process.exit(1);
}

try {
  commands[subcommand](rest);
} catch (err) {
  console.error(`Error: ${err.message}`);
  process.exit(1);
}
