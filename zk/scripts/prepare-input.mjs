import { createHash, randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { buildPoseidon } from "circomlibjs";

const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const SCALE = 256;
const BIAS = 32768;
const FEATURE_COUNT = 2;
const DATASET_DEPTH = 2;
const ORDERING_DEPTH = 4;
const DEFAULT_N = 4;
const DOMAIN = {
  dataLeaf: 201n,
  dataNode: 202n,
  orderLeaf: 203n,
  state: 204n,
  transition: 205n,
  orderNode: 206n,
  chain: 207n,
};

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const projectRoot = resolve(scriptDirectory, "..", "..");
const outputDir = resolve(process.argv[2] ?? "zk/demo-run");
const circuitPath = resolve(process.argv[3] ?? "zk/circuits/train_step.circom");
const nSteps = Number(process.argv[4] ?? DEFAULT_N);
if (!Number.isSafeInteger(nSteps) || nSteps < 1 || nSteps > 16) {
  throw new Error("N must be an integer in [1, 16]");
}
await mkdir(resolve(outputDir, "private"), { recursive: true });
await mkdir(resolve(outputDir, "public"), { recursive: true });

const poseidonImpl = await buildPoseidon();
const F = poseidonImpl.F;
const poseidon = (values) => BigInt(F.toString(poseidonImpl(values.map(BigInt))));
const randomField = () => BigInt(`0x${randomBytes(31).toString("hex")}`) % FIELD;
const shaField = (value) => BigInt(`0x${createHash("sha256").update(value).digest("hex")}`) % FIELD;
const asStrings = (values) => values.map((value) => BigInt(value).toString());
const nestedStrings = (rows) => rows.map(asStrings);
const encode = (raw) => BigInt(raw + BIAS);
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

function referenceTrajectory(initialStep, initialState, samples) {
  const python = process.env.PYTHON ?? "python";
  const request = JSON.stringify({ initialStep, initialState, samples });
  const completed = spawnSync(
    python,
    [resolve(projectRoot, "scripts", "fixed-point-reference.py")],
    { cwd: projectRoot, encoding: "utf8", input: request, windowsHide: true },
  );
  if (completed.error) throw completed.error;
  if (completed.status !== 0) {
    throw new Error(`fixed-point reference failed: ${(completed.stderr ?? "").trim()}`);
  }
  return JSON.parse(completed.stdout);
}

// Raw integers represent real values divided by 256.  This fixture exercises
// positive and negative inputs, errors, gradients, and floor remainders.
const records = [
  { x: [256, -128], y: 192 },
  { x: [-192, 64], y: -128 },
  { x: [128, 384], y: 256 },
  { x: [-256, -256], y: 64 },
];
const encodedRecords = records.map((record) => ({
  x: record.x.map(encode),
  y: encode(record.y),
}));
const recordSalts = records.map(() => randomField());
const datasetLeaves = encodedRecords.map((record, index) =>
  poseidon([
    DOMAIN.dataLeaf,
    BigInt(index),
    record.x[0],
    record.x[1],
    record.y,
    recordSalts[index],
  ]),
);
const datasetTree = buildTree(datasetLeaves, DOMAIN.dataNode);

const order = [0, 1, 2, 3, 1, 3, 0, 2, 2, 0, 3, 1, 3, 2, 1, 0];
const orderSalts = order.map(() => randomField());
const orderingLeaves = order.map((sampleIndex, step) =>
  poseidon([DOMAIN.orderLeaf, BigInt(step), BigInt(sampleIndex), orderSalts[step]]),
);
const orderingTree = buildTree(orderingLeaves, DOMAIN.orderNode);

const initialStep = 0;
if (initialStep + nSteps > order.length) {
  throw new Error("requested trajectory exceeds the committed ordering tree");
}
const initialState = { w: [64, -32], b: 16, counter: initialStep };
const selectedSamples = order.slice(initialStep, initialStep + nSteps).map((index) => records[index]);
const arithmetic = referenceTrajectory(initialStep, initialState, selectedSamples);
const stateSalts = Array.from({ length: nSteps + 1 }, () => randomField());
const stateCommitments = arithmetic.stateW.map((weights, index) =>
  poseidon([
    DOMAIN.state,
    BigInt(weights[0]),
    BigInt(weights[1]),
    BigInt(arithmetic.stateB[index]),
    BigInt(arithmetic.stateCounter[index]),
    stateSalts[index],
  ]),
);

const circuitBytes = await readFile(circuitPath);
const codeCommitment = shaField(circuitBytes);
const hyperparametersSpec = `fixed-point-linear-sgd/scale=256/raw=s16-offset-binary/round=floor/overflow=reject/features=2/lr-raw=16/n=${nSteps}/dataset-depth=2/order-depth=4/v2`;
const hyperparametersCommitment = shaField(Buffer.from(hyperparametersSpec, "utf8"));
const runId = randomBytes(16).toString("hex");
const runCommitmentMapping = "sha256-utf8-prefix-and-run-id-mod-bn254/v2";
const initialChain = shaField(Buffer.concat([
  Buffer.from("trainproof-zk-run/fixed-point-v2\0", "utf8"),
  Buffer.from(runId, "ascii"),
]));
const datasetRoot = datasetTree.at(-1)[0];
const orderingRoot = orderingTree.at(-1)[0];

const sampleIndices = order.slice(initialStep, initialStep + nSteps);
const dataProofs = sampleIndices.map((sampleIndex) => proofFor(datasetTree, sampleIndex));
const orderProofs = sampleIndices.map((_, offset) => proofFor(orderingTree, initialStep + offset));
const chains = [initialChain];
for (let offset = 0; offset < nSteps; offset += 1) {
  const step = initialStep + offset;
  const sampleIndex = sampleIndices[offset];
  const transitionDigest = poseidon([
    DOMAIN.transition,
    BigInt(step),
    datasetRoot,
    orderingRoot,
    codeCommitment,
    hyperparametersCommitment,
    datasetLeaves[sampleIndex],
    orderingLeaves[step],
    stateCommitments[offset],
    stateCommitments[offset + 1],
  ]);
  chains.push(poseidon([DOMAIN.chain, chains.at(-1), transitionDigest]));
}

const publicInputs = {
  initialStep: initialStep.toString(),
  transitionCount: nSteps.toString(),
  datasetRoot: datasetRoot.toString(),
  orderingRoot: orderingRoot.toString(),
  codeCommitment: codeCommitment.toString(),
  hyperparametersCommitment: hyperparametersCommitment.toString(),
  initialStateCommitment: stateCommitments[0].toString(),
  finalStateCommitment: stateCommitments.at(-1).toString(),
  initialChain: initialChain.toString(),
  finalChain: chains.at(-1).toString(),
};
const privateInput = {
  ...publicInputs,
  sampleIndex: sampleIndices.map(String),
  x: sampleIndices.map((index) => asStrings(encodedRecords[index].x)),
  y: sampleIndices.map((index) => encodedRecords[index].y.toString()),
  recordSalt: sampleIndices.map((index) => recordSalts[index].toString()),
  datasetSiblings: dataProofs.map((proof) => asStrings(proof.siblings)),
  datasetPathBits: dataProofs.map((proof) => asStrings(proof.bits)),
  orderSalt: sampleIndices.map((_, offset) => orderSalts[initialStep + offset].toString()),
  orderingSiblings: orderProofs.map((proof) => asStrings(proof.siblings)),
  orderingPathBits: orderProofs.map((proof) => asStrings(proof.bits)),
  stateW: nestedStrings(arithmetic.stateW),
  stateB: asStrings(arithmetic.stateB),
  stateCounter: asStrings(arithmetic.stateCounter),
  stateSalt: asStrings(stateSalts),
  dotScaled: asStrings(arithmetic.dotScaled),
  dotRemainder: asStrings(arithmetic.dotRemainder),
  prediction: asStrings(arithmetic.prediction),
  error: asStrings(arithmetic.error),
  gradients: nestedStrings(arithmetic.gradients),
  gradientRemainders: nestedStrings(arithmetic.gradientRemainders),
  weightSteps: nestedStrings(arithmetic.weightSteps),
  weightStepRemainders: nestedStrings(arithmetic.weightStepRemainders),
  biasStep: asStrings(arithmetic.biasStep),
  biasStepRemainder: asStrings(arithmetic.biasStepRemainder),
};

const fixedPointSpec = {
  scale: SCALE,
  fractionalBits: 8,
  rawRange: { minimum: -32768, maximum: 32767 },
  realRange: { minimumInclusive: "-128", maximumInclusive: "32767/256" },
  encoding: "offset-binary-u16: encoded=raw+32768",
  multiplication: "exact signed raw integer multiplication; two-feature dot product accumulated before rescaling",
  rescaling: "q=floor(n/256), n=256*q+r, 0<=r<256",
  rounding: "toward-negative-infinity",
  overflow: "relation-unsatisfied for any fixed-point input, named intermediate, or state outside signed-16; counter outside unsigned-32",
  fieldEmbedding: "encoded values are canonical integers in [0,65535] in BN254; decoded arithmetic is encoded-32768",
  learningRate: { raw: 16, exact: "1/16" },
  referenceImplementation: "src/trainproof/fixed_point.py",
};
const claims = {
  privateDatasetMembershipForEveryTransition: true,
  privateOrderingMembershipForEveryTransition: true,
  consecutiveOrderingPositions: true,
  initialStateOpening: true,
  intermediateStateContinuity: true,
  deterministicFixedPointTransitions: true,
  finalStateOpening: true,
  poseidonTransitionChain: true,
  checkpointOpening: true,
  unbiasedOrPermutationOrdering: false,
  historicalExecution: false,
  pytorchOrIeeeFloatingPoint: false,
};
const statement = {
  scheme: "circom-plonk-bn254/v2",
  relation: `bounded-fixed-point-linear-training-chain/n=${nSteps}/v2`,
  arithmetic: "signed 16-bit offset fixed point at scale 256 with floor rescaling and checked overflow",
  fieldCommitmentMapping: "unsigned-big-endian-sha256-mod-bn254/v1",
  fixedPointSpec,
  circuitProfile: {
    nSteps,
    featureCount: FEATURE_COUNT,
    datasetDepth: DATASET_DEPTH,
    orderingDepth: ORDERING_DEPTH,
  },
  hyperparametersSpec,
  runId,
  runCommitmentMapping,
  publicInputs,
  claims,
  privateWitnessSummary: {
    datasetSize: records.length,
    orderingLength: order.length,
    transitionCount: nSteps,
    featureCount: FEATURE_COUNT,
    revealedTrainingRecords: 0,
  },
  circuitSha256: createHash("sha256").update(circuitBytes).digest("hex"),
};

const finalIndex = arithmetic.stateW.length - 1;
const checkpointOpening = {
  w: asStrings(arithmetic.stateW[finalIndex]),
  b: BigInt(arithmetic.stateB[finalIndex]).toString(),
  counter: BigInt(arithmetic.stateCounter[finalIndex]).toString(),
  salt: stateSalts[finalIndex].toString(),
};

await writeFile(resolve(outputDir, "private", "input.json"), `${JSON.stringify(privateInput, null, 2)}\n`);
await writeFile(resolve(outputDir, "private", "checkpoint.opening.json"), `${JSON.stringify(checkpointOpening, null, 2)}\n`);
await writeFile(resolve(outputDir, "public", "statement.json"), `${JSON.stringify(statement, null, 2)}\n`);
console.log(JSON.stringify({ outputDir, nSteps, publicInputs, privateInput: "written but not printed" }, null, 2));
