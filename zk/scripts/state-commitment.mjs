import { buildPoseidon } from "circomlibjs";

const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const values = process.argv.slice(2);
if (values.length !== 5 || values.some((value) => !/^(0|[1-9][0-9]*)$/.test(value))) {
  throw new Error("expected w[0], w[1], b, counter, and salt as canonical non-negative decimals");
}
const elements = values.map(BigInt);
if (
  elements[0] >= 65536n
  || elements[1] >= 65536n
  || elements[2] >= 65536n
  || elements[3] >= 4294967296n
  || elements[4] >= FIELD
) {
  throw new Error("state opening element is outside the fixed-point v2 range");
}
const poseidon = await buildPoseidon();
const commitment = poseidon([204n, ...elements]);
process.stdout.write(`${poseidon.F.toString(commitment)}\n`);
