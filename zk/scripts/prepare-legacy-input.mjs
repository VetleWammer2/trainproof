import { createHash, randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { buildPoseidon } from "circomlibjs";

const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const DOMAIN = { dataLeaf: 101n, dataNode: 102n, orderLeaf: 103n, state: 104n, step: 105n, orderNode: 106n };
const outputDir = resolve(process.argv[2]);
const circuitPath = resolve(process.argv[3]);
await mkdir(outputDir, { recursive: true });

const implementation = await buildPoseidon();
const F = implementation.F;
const poseidon = (values) => BigInt(F.toString(implementation(values.map(BigInt))));
const randomField = () => BigInt(`0x${randomBytes(31).toString("hex")}`) % FIELD;
const shaField = (value) => BigInt(`0x${createHash("sha256").update(value).digest("hex")}`) % FIELD;
const nodeHash = (domain, left, right) => poseidon([domain, left, right]);
const strings = (values) => values.map((value) => value.toString());

function tree(leaves, domain) {
  const levels = [leaves];
  while (levels.at(-1).length > 1) {
    const current = levels.at(-1);
    const next = [];
    for (let index = 0; index < current.length; index += 2) {
      next.push(nodeHash(domain, current[index], current[index + 1]));
    }
    levels.push(next);
  }
  return levels;
}

function proof(levels, index) {
  const siblings = [];
  const bits = [];
  let cursor = index;
  for (const level of levels.slice(0, -1)) {
    siblings.push(level[cursor ^ 1]);
    bits.push(BigInt(cursor & 1));
    cursor >>= 1;
  }
  return { siblings, bits };
}

const records = [{ x: 1n, y: 2n }, { x: 2n, y: 5n }, { x: 3n, y: 9n }, { x: 4n, y: 14n }];
const recordSalts = records.map(randomField);
const dataLeaves = records.map((record, index) => poseidon([DOMAIN.dataLeaf, BigInt(index), record.x, record.y, recordSalts[index]]));
const dataTree = tree(dataLeaves, DOMAIN.dataNode);
const order = [0, 2, 1, 3, 2, 0, 3, 1, 1, 3, 0, 2, 3, 1, 2, 0];
const orderSalts = order.map(randomField);
const orderLeaves = order.map((sampleIndex, step) => poseidon([DOMAIN.orderLeaf, BigInt(step), BigInt(sampleIndex), orderSalts[step]]));
const orderTree = tree(orderLeaves, DOMAIN.orderNode);
const step = 0;
const sampleIndex = order[step];
const sample = records[sampleIndex];
const dataProof = proof(dataTree, sampleIndex);
const orderProof = proof(orderTree, step);
const oldW = 0n;
const oldB = 0n;
const oldRng = 7n;
const prediction = oldW * sample.x + oldB;
const delta = sample.y - prediction;
const newW = oldW + delta * sample.x;
const newB = oldB + delta;
const newRng = oldRng + 1n;
const oldStateSalt = randomField();
const newStateSalt = randomField();
const oldStateCommitment = poseidon([DOMAIN.state, oldW, oldB, oldRng, oldStateSalt]);
const newStateCommitment = poseidon([DOMAIN.state, newW, newB, newRng, newStateSalt]);
const circuitBytes = await readFile(circuitPath);
const codeCommitment = shaField(circuitBytes);
const hyperparametersCommitment = shaField(Buffer.from("bounded-unsigned-linear-update/lr=1/dataset-depth=2/order-depth=4/v1"));
const runId = randomBytes(16).toString("hex");
const prevChain = shaField(Buffer.concat([
  Buffer.from("trainproof-zk-run/v1\0"),
  Buffer.from(runId, "ascii"),
]));
const datasetRoot = dataTree.at(-1)[0];
const orderingRoot = orderTree.at(-1)[0];
const nextChain = poseidon([DOMAIN.step, prevChain, BigInt(step), datasetRoot, orderingRoot, codeCommitment, hyperparametersCommitment, oldStateCommitment, newStateCommitment]);
const input = {
  step: "0",
  datasetRoot: datasetRoot.toString(),
  orderingRoot: orderingRoot.toString(),
  codeCommitment: codeCommitment.toString(),
  hyperparametersCommitment: hyperparametersCommitment.toString(),
  oldStateCommitment: oldStateCommitment.toString(),
  newStateCommitment: newStateCommitment.toString(),
  prevChain: prevChain.toString(),
  nextChain: nextChain.toString(),
  sampleIndex: sampleIndex.toString(),
  x: sample.x.toString(),
  y: sample.y.toString(),
  recordSalt: recordSalts[sampleIndex].toString(),
  datasetSiblings: strings(dataProof.siblings),
  datasetPathBits: strings(dataProof.bits),
  orderSalt: orderSalts[step].toString(),
  orderingSiblings: strings(orderProof.siblings),
  orderingPathBits: strings(orderProof.bits),
  oldW: oldW.toString(),
  oldB: oldB.toString(),
  oldRng: oldRng.toString(),
  oldStateSalt: oldStateSalt.toString(),
  newStateSalt: newStateSalt.toString(),
};
await writeFile(resolve(outputDir, "input.json"), `${JSON.stringify(input, null, 2)}\n`);
