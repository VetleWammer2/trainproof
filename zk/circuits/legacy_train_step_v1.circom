pragma circom 2.2.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

// Preserved only as the measured pre-fixed-point baseline from main@da41c02.
template LegacyMerklePath(depth, nodeDomain) {
    signal input leaf;
    signal input siblings[depth];
    signal input pathBits[depth];
    signal output root;

    signal current[depth + 1];
    signal left[depth];
    signal right[depth];
    component hashers[depth];

    current[0] <== leaf;
    for (var level = 0; level < depth; level++) {
        pathBits[level] * (pathBits[level] - 1) === 0;
        left[level] <== current[level] + pathBits[level] * (siblings[level] - current[level]);
        right[level] <== siblings[level] + pathBits[level] * (current[level] - siblings[level]);
        hashers[level] = Poseidon(3);
        hashers[level].inputs[0] <== nodeDomain;
        hashers[level].inputs[1] <== left[level];
        hashers[level].inputs[2] <== right[level];
        current[level + 1] <== hashers[level].out;
    }
    root <== current[depth];
}

template LegacyTrainStep(datasetDepth, orderingDepth) {
    signal input step;
    signal input datasetRoot;
    signal input orderingRoot;
    signal input codeCommitment;
    signal input hyperparametersCommitment;
    signal input oldStateCommitment;
    signal input newStateCommitment;
    signal input prevChain;
    signal input nextChain;

    signal input sampleIndex;
    signal input x;
    signal input y;
    signal input recordSalt;
    signal input datasetSiblings[datasetDepth];
    signal input datasetPathBits[datasetDepth];
    signal input orderSalt;
    signal input orderingSiblings[orderingDepth];
    signal input orderingPathBits[orderingDepth];
    signal input oldW;
    signal input oldB;
    signal input oldRng;
    signal input oldStateSalt;
    signal input newStateSalt;

    component stepBits = Num2Bits(orderingDepth);
    stepBits.in <== step;
    component indexBits = Num2Bits(datasetDepth);
    indexBits.in <== sampleIndex;
    for (var dataLevel = 0; dataLevel < datasetDepth; dataLevel++) {
        datasetPathBits[dataLevel] === indexBits.out[dataLevel];
    }
    for (var orderLevel = 0; orderLevel < orderingDepth; orderLevel++) {
        orderingPathBits[orderLevel] === stepBits.out[orderLevel];
    }

    component xRange = Num2Bits(16);
    component yRange = Num2Bits(16);
    component oldWRange = Num2Bits(16);
    component oldBRange = Num2Bits(16);
    component oldRngRange = Num2Bits(32);
    xRange.in <== x;
    yRange.in <== y;
    oldWRange.in <== oldW;
    oldBRange.in <== oldB;
    oldRngRange.in <== oldRng;

    component dataLeaf = Poseidon(5);
    dataLeaf.inputs[0] <== 101;
    dataLeaf.inputs[1] <== sampleIndex;
    dataLeaf.inputs[2] <== x;
    dataLeaf.inputs[3] <== y;
    dataLeaf.inputs[4] <== recordSalt;
    component dataPath = LegacyMerklePath(datasetDepth, 102);
    dataPath.leaf <== dataLeaf.out;
    for (var i = 0; i < datasetDepth; i++) {
        dataPath.siblings[i] <== datasetSiblings[i];
        dataPath.pathBits[i] <== datasetPathBits[i];
    }
    dataPath.root === datasetRoot;

    component orderLeaf = Poseidon(4);
    orderLeaf.inputs[0] <== 103;
    orderLeaf.inputs[1] <== step;
    orderLeaf.inputs[2] <== sampleIndex;
    orderLeaf.inputs[3] <== orderSalt;
    component orderPath = LegacyMerklePath(orderingDepth, 106);
    orderPath.leaf <== orderLeaf.out;
    for (var j = 0; j < orderingDepth; j++) {
        orderPath.siblings[j] <== orderingSiblings[j];
        orderPath.pathBits[j] <== orderingPathBits[j];
    }
    orderPath.root === orderingRoot;

    component oldState = Poseidon(5);
    oldState.inputs[0] <== 104;
    oldState.inputs[1] <== oldW;
    oldState.inputs[2] <== oldB;
    oldState.inputs[3] <== oldRng;
    oldState.inputs[4] <== oldStateSalt;
    oldState.out === oldStateCommitment;

    signal prediction;
    signal delta;
    signal newW;
    signal newB;
    signal newRng;
    prediction <== oldW * x + oldB;
    component predictionRange = Num2Bits(33);
    predictionRange.in <== prediction;
    component predictionAtMostY = LessEqThan(33);
    predictionAtMostY.in[0] <== prediction;
    predictionAtMostY.in[1] <== y;
    predictionAtMostY.out === 1;
    delta <== y - prediction;
    component deltaRange = Num2Bits(16);
    deltaRange.in <== delta;
    newW <== oldW + delta * x;
    newB <== oldB + delta;
    newRng <== oldRng + 1;
    component newWRange = Num2Bits(33);
    component newBRange = Num2Bits(17);
    component newRngRange = Num2Bits(32);
    newWRange.in <== newW;
    newBRange.in <== newB;
    newRngRange.in <== newRng;

    component newState = Poseidon(5);
    newState.inputs[0] <== 104;
    newState.inputs[1] <== newW;
    newState.inputs[2] <== newB;
    newState.inputs[3] <== newRng;
    newState.inputs[4] <== newStateSalt;
    newState.out === newStateCommitment;

    component chain = Poseidon(9);
    chain.inputs[0] <== 105;
    chain.inputs[1] <== prevChain;
    chain.inputs[2] <== step;
    chain.inputs[3] <== datasetRoot;
    chain.inputs[4] <== orderingRoot;
    chain.inputs[5] <== codeCommitment;
    chain.inputs[6] <== hyperparametersCommitment;
    chain.inputs[7] <== oldStateCommitment;
    chain.inputs[8] <== newStateCommitment;
    chain.out === nextChain;
}

component main {public [
    step,
    datasetRoot,
    orderingRoot,
    codeCommitment,
    hyperparametersCommitment,
    oldStateCommitment,
    newStateCommitment,
    prevChain,
    nextChain
]} = LegacyTrainStep(2, 4);
