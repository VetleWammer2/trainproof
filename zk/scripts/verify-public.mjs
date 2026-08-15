import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const symPath = resolve(process.argv[2]);
const publicPath = resolve(process.argv[3]);
const statementPath = resolve(process.argv[4]);
const publicSignals = JSON.parse(await readFile(publicPath, "utf8"));
const statement = JSON.parse(await readFile(statementPath, "utf8"));
const sym = await readFile(symPath, "utf8");

const normalized = (value) => ((BigInt(value) % FIELD) + FIELD) % FIELD;
const signalToWitness = new Map();
for (const line of sym.trim().split(/\r?\n/u)) {
  const [labelIndex, witnessIndex, componentIndex, name] = line.split(",");
  if (name?.startsWith("main.")) signalToWitness.set(name, Number(witnessIndex));
}

const checked = {};
for (const [name, expected] of Object.entries(statement.publicInputs)) {
  const witnessIndex = signalToWitness.get(`main.${name}`);
  if (!Number.isInteger(witnessIndex) || witnessIndex < 1 || witnessIndex > publicSignals.length) {
    throw new Error(`public signal ${name} is missing from circuit symbols`);
  }
  const actual = publicSignals[witnessIndex - 1];
  if (normalized(actual) !== normalized(expected)) {
    throw new Error(`public signal mismatch for ${name}: expected ${expected}, got ${actual}`);
  }
  checked[name] = actual;
}
if (Object.keys(checked).length !== publicSignals.length) {
  throw new Error(`unexpected public signal count: statement has ${Object.keys(checked).length}, proof has ${publicSignals.length}`);
}
console.log(JSON.stringify({ valid: true, checked }, null, 2));

