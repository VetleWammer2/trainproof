import { createHash, randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { buildPoseidon } from "circomlibjs";

const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const DOMAIN = {
  dataLeaf: 101n,
  dataNode: 102n,
  orderLeaf: 103n,
  state: 104n,
  step: 105n,
  orderNode: 106n,
};

const outputDir = resolve(process.argv[2] ?? "zk/demo-run");
const circuitPath = resolve(process.argv[3] ?? "zk/circuits/train_step.circom");
await mkdir(resolve(outputDir, "private"), { recursive: true });
await mkdir(resolve(outputDir, "public"), { recursive: true });

const poseidonImpl = await buildPoseidon();
const F = poseidonImpl.F;
const poseidon = (values) => BigInt(F.toString(poseidonImpl(values.map(BigInt))));
const randomField = () => BigInt(`0x${randomBytes(31).toString("hex")}`) % FIELD;
const shaField = (value) => BigInt(`0x${createHash("sha256").update(value).digest("hex")}`) % FIELD;
const asStrings = (values) => values.map((value) => value.toString());
const nodeHash = (domain, left, right) => poseidon([domain, left, right]);

function buildTree(leaves, nodeDomain) {
  const levels = [leaves];
  while (levels.at(-1).length > 1) {
    const current = levels.at(-1);
    const next = [];
    for (let i = 0; i < current.length; i += 2) {
      next.push(nodeHash(nodeDomain, current[i], current[i + 1]));
    }
    levels.push(next);
  }
  return levels;
}

function proofFor(levels, index) {
  const siblings = [];
  const bits = [];
  let cursor = index;
  for (let level = 0; level < levels.length - 1; level += 1) {
    bits.push(BigInt(cursor & 1));
    siblings.push(levels[level][cursor ^ 1]);
    cursor >>= 1;
  }
  return { siblings, bits };
}

const records = [
  { x: 1n, y: 2n },
  { x: 2n, y: 5n },
  { x: 3n, y: 9n },
  { x: 4n, y: 14n },
];
const recordSalts = records.map(() => randomField());
const datasetLeaves = records.map((record, index) =>
  poseidon([DOMAIN.dataLeaf, BigInt(index), record.x, record.y, recordSalts[index]]),
);
const datasetTree = buildTree(datasetLeaves, DOMAIN.dataNode);

const order = [0, 2, 1, 3, 2, 0, 3, 1, 1, 3, 0, 2, 3, 1, 2, 0];
const orderSalts = order.map(() => randomField());
const orderingLeaves = order.map((sampleIndex, step) =>
  poseidon([DOMAIN.orderLeaf, BigInt(step), BigInt(sampleIndex), orderSalts[step]]),
);
const orderingTree = buildTree(orderingLeaves, DOMAIN.orderNode);

const step = 0;
const sampleIndex = order[step];
const sample = records[sampleIndex];
const dataProof = proofFor(datasetTree, sampleIndex);
const orderProof = proofFor(orderingTree, step);
const oldW = 0n;
const oldB = 0n;
const oldRng = 7n;
const prediction = oldW * sample.x + oldB;
const delta = sample.y - prediction;
if (delta < 0n) throw new Error("demo witness violates unsigned residual constraint");
const newW = oldW + delta * sample.x;
const newB = oldB + delta;
const newRng = oldRng + 1n;
const oldStateSalt = randomField();
const newStateSalt = randomField();
const oldStateCommitment = poseidon([DOMAIN.state, oldW, oldB, oldRng, oldStateSalt]);
const newStateCommitment = poseidon([DOMAIN.state, newW, newB, newRng, newStateSalt]);
const circuitBytes = await readFile(circuitPath);
const codeCommitment = shaField(circuitBytes);
const hyperparametersSpec = "bounded-unsigned-linear-update/lr=1/dataset-depth=2/order-depth=4/v1";
const hyperparameters = Buffer.from(hyperparametersSpec);
const hyperparametersCommitment = shaField(hyperparameters);
const runId = randomBytes(16).toString("hex");
const runCommitmentMapping = "sha256-utf8-prefix-and-run-id-mod-bn254/v1";
const prevChain = shaField(Buffer.concat([
  Buffer.from("trainproof-zk-run/v1\0", "utf8"),
  Buffer.from(runId, "ascii"),
]));
const datasetRoot = datasetTree.at(-1)[0];
const orderingRoot = orderingTree.at(-1)[0];
const nextChain = poseidon([
  DOMAIN.step,
  prevChain,
  BigInt(step),
  datasetRoot,
  orderingRoot,
  codeCommitment,
  hyperparametersCommitment,
  oldStateCommitment,
  newStateCommitment,
]);

const publicInputs = {
  step: step.toString(),
  datasetRoot: datasetRoot.toString(),
  orderingRoot: orderingRoot.toString(),
  codeCommitment: codeCommitment.toString(),
  hyperparametersCommitment: hyperparametersCommitment.toString(),
  oldStateCommitment: oldStateCommitment.toString(),
  newStateCommitment: newStateCommitment.toString(),
  prevChain: prevChain.toString(),
  nextChain: nextChain.toString(),
};
const privateInput = {
  ...publicInputs,
  sampleIndex: sampleIndex.toString(),
  x: sample.x.toString(),
  y: sample.y.toString(),
  recordSalt: recordSalts[sampleIndex].toString(),
  datasetSiblings: asStrings(dataProof.siblings),
  datasetPathBits: asStrings(dataProof.bits),
  orderSalt: orderSalts[step].toString(),
  orderingSiblings: asStrings(orderProof.siblings),
  orderingPathBits: asStrings(orderProof.bits),
  oldW: oldW.toString(),
  oldB: oldB.toString(),
  oldRng: oldRng.toString(),
  oldStateSalt: oldStateSalt.toString(),
  newStateSalt: newStateSalt.toString(),
};
const statement = {
  scheme: "circom-plonk-bn254/v1",
  relation: "bounded-unsigned-linear-training-step/v1",
  arithmetic: "BN254 field with explicit unsigned range constraints",
  fieldCommitmentMapping: "unsigned-big-endian-sha256-mod-bn254/v1",
  hyperparametersSpec,
  runId,
  runCommitmentMapping,
  publicInputs,
  claims: {
    privateDatasetMembership: true,
    privateOrderingMembership: true,
    oldStateOpening: true,
    deterministicTransition: true,
    newStateOpening: true,
    poseidonChainTransition: true,
    checkpointOpening: true,
    unbiasedOrPermutationOrdering: false,
    pytorchOrIeeeFloatingPoint: false,
  },
  privateWitnessSummary: {
    datasetSize: records.length,
    orderingLength: order.length,
    revealedTrainingRecords: 0,
  },
  circuitSha256: createHash("sha256").update(circuitBytes).digest("hex"),
};

const checkpointOpening = {
  w: newW.toString(),
  b: newB.toString(),
  rng: newRng.toString(),
  salt: newStateSalt.toString(),
};

await writeFile(resolve(outputDir, "private", "input.json"), `${JSON.stringify(privateInput, null, 2)}\n`);
await writeFile(resolve(outputDir, "private", "checkpoint.opening.json"), `${JSON.stringify(checkpointOpening, null, 2)}\n`);
await writeFile(resolve(outputDir, "public", "statement.json"), `${JSON.stringify(statement, null, 2)}\n`);
console.log(JSON.stringify({ outputDir, publicInputs, privateInput: "written but not printed" }, null, 2));
