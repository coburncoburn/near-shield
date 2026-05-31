#!/usr/bin/env node
// ceremony/scripts/manifest.mjs
// Maintains ceremony/out/manifest.json (or $CEREMONY_OUT/manifest.json).
// Usage:
//   node manifest.mjs init <ptauPath>
//   node manifest.mjs add-contribution <circuit> <name> <contributionHash>
//   node manifest.mjs set-beacon <circuit> <beaconHex> <source>
//   node manifest.mjs finalize-circuit <circuit> <zkeyPath> <vkJsonPath> <vkBinPath>

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
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
  const abs = resolve(ptauPath);
  const sha256 = sha256Hex(abs);
  const manifest = {
    ptau: { path: abs, sha256, power: POWER },
    circuits: {},
  };
  writeManifest(manifest);
}

function cmdAddContribution(args) {
  const [circuit, name, contributionHash] = args;
  if (!circuit || !name || !contributionHash) {
    throw new Error('Usage: add-contribution <circuit> <name> <contributionHash>');
  }
  const manifest = readManifest();
  if (!manifest.circuits[circuit]) {
    manifest.circuits[circuit] = { contributions: [] };
  }
  if (!manifest.circuits[circuit].contributions) {
    manifest.circuits[circuit].contributions = [];
  }
  manifest.circuits[circuit].contributions.push({ name, contributionHash });
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

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

const [, , subcommand, ...rest] = process.argv;

const commands = {
  'init': cmdInit,
  'add-contribution': cmdAddContribution,
  'set-beacon': cmdSetBeacon,
  'finalize-circuit': cmdFinalizeCircuit,
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
