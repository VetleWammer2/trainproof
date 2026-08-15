import { buildPoseidon } from "circomlibjs";

const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const values = process.argv.slice(2);
if (values.length !== 4 || values.some((value) => !/^(0|[1-9][0-9]*)$/.test(value))) {
  throw new Error("expected four canonical non-negative decimal field elements");
}
const elements = values.map(BigInt);
if (elements.some((value) => value >= FIELD)) {
  throw new Error("field element out of range");
}
const poseidon = await buildPoseidon();
const commitment = poseidon([104n, ...elements]);
process.stdout.write(`${poseidon.F.toString(commitment)}\n`);
