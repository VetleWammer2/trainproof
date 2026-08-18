pragma circom 2.2.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";

// Fixed-point profile v2:
//   encoded = raw + 2^15, raw in [-2^15, 2^15-1], real = raw / 256.
// Rescaling is floor(numerator / 256). Every quotient is again signed-16;
// an out-of-range intermediate or state therefore makes the relation fail.
// The largest numerator below is a two-term signed-16 dot product, whose
// absolute value is at most 2^31. Adding 2^32 keeps the integer relation
// positive and far below the BN254 modulus.

template MerklePath(depth, nodeDomain) {
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

template DecodeFixed16() {
    signal input encoded;
    signal output value;

    component range = Num2Bits(16);
    range.in <== encoded;
    value <== encoded - 32768;
}

template FloorRescaleFixed16() {
    signal input numerator;
    signal input encodedQuotient;
    signal input remainder;
    signal output quotient;

    component quotientRange = Num2Bits(16);
    component remainderRange = Num2Bits(8);
    quotientRange.in <== encodedQuotient;
    remainderRange.in <== remainder;

    // Let q = encodedQuotient - 2^15 and D = 2^32. Because D is a
    // multiple of 256, this is exactly numerator = 256*q + remainder,
    // with 0 <= remainder < 256. That uniquely defines floor division,
    // including for negative numerators.
    numerator + 4294967296 === (encodedQuotient + 16744448) * 256 + remainder;
    quotient <== encodedQuotient - 32768;
}

template FixedPointTransition(datasetDepth, orderingDepth) {
    // Shared public statement.
    signal input absoluteStep;
    signal input datasetRoot;
    signal input orderingRoot;
    signal input codeCommitment;
    signal input hyperparametersCommitment;

    // Private dataset and ordering openings.
    signal input sampleIndex;
    signal input x[2];
    signal input y;
    signal input recordSalt;
    signal input datasetSiblings[datasetDepth];
    signal input datasetPathBits[datasetDepth];
    signal input orderSalt;
    signal input orderingSiblings[orderingDepth];
    signal input orderingPathBits[orderingDepth];

    // Decoded state values are range-constrained once by the parent.
    signal input oldW[2];
    signal input oldB;
    signal input newW[2];
    signal input newB;
    signal input oldStateCommitment;
    signal input newStateCommitment;

    // Integer-division witnesses and range-constrained intermediates.
    signal input dotScaled;
    signal input dotRemainder;
    signal input prediction;
    signal input error;
    signal input gradients[2];
    signal input gradientRemainders[2];
    signal input weightSteps[2];
    signal input weightStepRemainders[2];
    signal input biasStep;
    signal input biasStepRemainder;

    signal input previousChain;
    signal output nextChain;

    component stepBits = Num2Bits(orderingDepth);
    component indexBits = Num2Bits(datasetDepth);
    stepBits.in <== absoluteStep;
    indexBits.in <== sampleIndex;
    for (var dataLevel = 0; dataLevel < datasetDepth; dataLevel++) {
        datasetPathBits[dataLevel] === indexBits.out[dataLevel];
    }
    for (var orderLevel = 0; orderLevel < orderingDepth; orderLevel++) {
        orderingPathBits[orderLevel] === stepBits.out[orderLevel];
    }

    component decodedX[2];
    component decodedY = DecodeFixed16();
    for (var feature = 0; feature < 2; feature++) {
        decodedX[feature] = DecodeFixed16();
        decodedX[feature].encoded <== x[feature];
    }
    decodedY.encoded <== y;

    // v2 domains 201..207 are distinct from the unsigned scalar v1 circuit.
    component dataLeaf = Poseidon(6);
    dataLeaf.inputs[0] <== 201;
    dataLeaf.inputs[1] <== sampleIndex;
    dataLeaf.inputs[2] <== x[0];
    dataLeaf.inputs[3] <== x[1];
    dataLeaf.inputs[4] <== y;
    dataLeaf.inputs[5] <== recordSalt;
    component dataPath = MerklePath(datasetDepth, 202);
    dataPath.leaf <== dataLeaf.out;
    for (var i = 0; i < datasetDepth; i++) {
        dataPath.siblings[i] <== datasetSiblings[i];
        dataPath.pathBits[i] <== datasetPathBits[i];
    }
    dataPath.root === datasetRoot;

    component orderLeaf = Poseidon(4);
    orderLeaf.inputs[0] <== 203;
    orderLeaf.inputs[1] <== absoluteStep;
    orderLeaf.inputs[2] <== sampleIndex;
    orderLeaf.inputs[3] <== orderSalt;
    component orderPath = MerklePath(orderingDepth, 206);
    orderPath.leaf <== orderLeaf.out;
    for (var j = 0; j < orderingDepth; j++) {
        orderPath.siblings[j] <== orderingSiblings[j];
        orderPath.pathBits[j] <== orderingPathBits[j];
    }
    orderPath.root === orderingRoot;

    // prediction = floor((w[0]*x[0] + w[1]*x[1]) / 256) + b
    signal dotProducts[2];
    dotProducts[0] <== oldW[0] * decodedX[0].value;
    dotProducts[1] <== oldW[1] * decodedX[1].value;
    component dot = FloorRescaleFixed16();
    dot.numerator <== dotProducts[0] + dotProducts[1];
    dot.encodedQuotient <== dotScaled;
    dot.remainder <== dotRemainder;

    component decodedPrediction = DecodeFixed16();
    component decodedError = DecodeFixed16();
    decodedPrediction.encoded <== prediction;
    decodedPrediction.value === dot.quotient + oldB;
    decodedError.encoded <== error;
    decodedError.value === decodedPrediction.value - decodedY.value;

    // grad_w[j] = floor(error*x[j]/256), update_w[j] = floor(grad_w[j]*16/256).
    component gradientScale[2];
    component weightStepScale[2];
    for (var k = 0; k < 2; k++) {
        gradientScale[k] = FloorRescaleFixed16();
        gradientScale[k].numerator <== decodedError.value * decodedX[k].value;
        gradientScale[k].encodedQuotient <== gradients[k];
        gradientScale[k].remainder <== gradientRemainders[k];

        weightStepScale[k] = FloorRescaleFixed16();
        weightStepScale[k].numerator <== gradientScale[k].quotient * 16;
        weightStepScale[k].encodedQuotient <== weightSteps[k];
        weightStepScale[k].remainder <== weightStepRemainders[k];
        newW[k] === oldW[k] - weightStepScale[k].quotient;
    }

    // update_b = floor(error*16/256); new state is old state - update.
    component biasStepScale = FloorRescaleFixed16();
    biasStepScale.numerator <== decodedError.value * 16;
    biasStepScale.encodedQuotient <== biasStep;
    biasStepScale.remainder <== biasStepRemainder;
    newB === oldB - biasStepScale.quotient;

    // Absorb the exact opened record/order leaves and shared state endpoints,
    // then advance a binary Poseidon chain. Every transition is absorbed in
    // circuit order and cannot be dropped, inserted, or reordered at fixed N.
    component transitionDigest = Poseidon(10);
    transitionDigest.inputs[0] <== 205;
    transitionDigest.inputs[1] <== absoluteStep;
    transitionDigest.inputs[2] <== datasetRoot;
    transitionDigest.inputs[3] <== orderingRoot;
    transitionDigest.inputs[4] <== codeCommitment;
    transitionDigest.inputs[5] <== hyperparametersCommitment;
    transitionDigest.inputs[6] <== dataLeaf.out;
    transitionDigest.inputs[7] <== orderLeaf.out;
    transitionDigest.inputs[8] <== oldStateCommitment;
    transitionDigest.inputs[9] <== newStateCommitment;

    component chain = Poseidon(3);
    chain.inputs[0] <== 207;
    chain.inputs[1] <== previousChain;
    chain.inputs[2] <== transitionDigest.out;
    nextChain <== chain.out;
}

template TrainSteps(nSteps, datasetDepth, orderingDepth) {
    // Public circuit/version contract. transitionCount is constrained to the
    // compile-time nSteps; this production profile instantiates nSteps=4.
    signal input initialStep;
    signal input transitionCount;
    signal input datasetRoot;
    signal input orderingRoot;
    signal input codeCommitment;
    signal input hyperparametersCommitment;
    signal input initialStateCommitment;
    signal input finalStateCommitment;
    signal input initialChain;
    signal input finalChain;

    signal input sampleIndex[nSteps];
    signal input x[nSteps][2];
    signal input y[nSteps];
    signal input recordSalt[nSteps];
    signal input datasetSiblings[nSteps][datasetDepth];
    signal input datasetPathBits[nSteps][datasetDepth];
    signal input orderSalt[nSteps];
    signal input orderingSiblings[nSteps][orderingDepth];
    signal input orderingPathBits[nSteps][orderingDepth];

    // N transitions share N+1 states. The counter is the absolute next sample
    // position, so stateCounter[i] must equal initialStep+i.
    signal input stateW[nSteps + 1][2];
    signal input stateB[nSteps + 1];
    signal input stateCounter[nSteps + 1];
    signal input stateSalt[nSteps + 1];

    signal input dotScaled[nSteps];
    signal input dotRemainder[nSteps];
    signal input prediction[nSteps];
    signal input error[nSteps];
    signal input gradients[nSteps][2];
    signal input gradientRemainders[nSteps][2];
    signal input weightSteps[nSteps][2];
    signal input weightStepRemainders[nSteps][2];
    signal input biasStep[nSteps];
    signal input biasStepRemainder[nSteps];

    component stateWDecoded[nSteps + 1][2];
    component stateBDecoded[nSteps + 1];
    component stateCounterRange[nSteps + 1];
    component stateHasher[nSteps + 1];
    signal stateCommitments[nSteps + 1];
    for (var state = 0; state < nSteps + 1; state++) {
        for (var coordinate = 0; coordinate < 2; coordinate++) {
            stateWDecoded[state][coordinate] = DecodeFixed16();
            stateWDecoded[state][coordinate].encoded <== stateW[state][coordinate];
        }
        stateBDecoded[state] = DecodeFixed16();
        stateBDecoded[state].encoded <== stateB[state];
        stateCounterRange[state] = Num2Bits(32);
        stateCounterRange[state].in <== stateCounter[state];
        stateCounter[state] === initialStep + state;

        stateHasher[state] = Poseidon(6);
        stateHasher[state].inputs[0] <== 204;
        stateHasher[state].inputs[1] <== stateW[state][0];
        stateHasher[state].inputs[2] <== stateW[state][1];
        stateHasher[state].inputs[3] <== stateB[state];
        stateHasher[state].inputs[4] <== stateCounter[state];
        stateHasher[state].inputs[5] <== stateSalt[state];
        stateCommitments[state] <== stateHasher[state].out;
    }
    stateCommitments[0] === initialStateCommitment;
    stateCommitments[nSteps] === finalStateCommitment;
    transitionCount === nSteps;

    component transitions[nSteps];
    signal chains[nSteps + 1];
    chains[0] <== initialChain;
    for (var transition = 0; transition < nSteps; transition++) {
        transitions[transition] = FixedPointTransition(datasetDepth, orderingDepth);
        transitions[transition].absoluteStep <== initialStep + transition;
        transitions[transition].datasetRoot <== datasetRoot;
        transitions[transition].orderingRoot <== orderingRoot;
        transitions[transition].codeCommitment <== codeCommitment;
        transitions[transition].hyperparametersCommitment <== hyperparametersCommitment;
        transitions[transition].sampleIndex <== sampleIndex[transition];
        transitions[transition].y <== y[transition];
        transitions[transition].recordSalt <== recordSalt[transition];
        transitions[transition].orderSalt <== orderSalt[transition];
        for (var feature = 0; feature < 2; feature++) {
            transitions[transition].x[feature] <== x[transition][feature];
            transitions[transition].oldW[feature] <== stateWDecoded[transition][feature].value;
            transitions[transition].newW[feature] <== stateWDecoded[transition + 1][feature].value;
            transitions[transition].gradients[feature] <== gradients[transition][feature];
            transitions[transition].gradientRemainders[feature] <== gradientRemainders[transition][feature];
            transitions[transition].weightSteps[feature] <== weightSteps[transition][feature];
            transitions[transition].weightStepRemainders[feature] <== weightStepRemainders[transition][feature];
        }
        for (var dataLevel = 0; dataLevel < datasetDepth; dataLevel++) {
            transitions[transition].datasetSiblings[dataLevel] <== datasetSiblings[transition][dataLevel];
            transitions[transition].datasetPathBits[dataLevel] <== datasetPathBits[transition][dataLevel];
        }
        for (var orderLevel = 0; orderLevel < orderingDepth; orderLevel++) {
            transitions[transition].orderingSiblings[orderLevel] <== orderingSiblings[transition][orderLevel];
            transitions[transition].orderingPathBits[orderLevel] <== orderingPathBits[transition][orderLevel];
        }
        transitions[transition].oldB <== stateBDecoded[transition].value;
        transitions[transition].newB <== stateBDecoded[transition + 1].value;
        transitions[transition].oldStateCommitment <== stateCommitments[transition];
        transitions[transition].newStateCommitment <== stateCommitments[transition + 1];
        transitions[transition].dotScaled <== dotScaled[transition];
        transitions[transition].dotRemainder <== dotRemainder[transition];
        transitions[transition].prediction <== prediction[transition];
        transitions[transition].error <== error[transition];
        transitions[transition].biasStep <== biasStep[transition];
        transitions[transition].biasStepRemainder <== biasStepRemainder[transition];
        transitions[transition].previousChain <== chains[transition];
        chains[transition + 1] <== transitions[transition].nextChain;
    }
    chains[nSteps] === finalChain;
}

component main {public [
    initialStep,
    transitionCount,
    datasetRoot,
    orderingRoot,
    codeCommitment,
    hyperparametersCommitment,
    initialStateCommitment,
    finalStateCommitment,
    initialChain,
    finalChain
]} = TrainSteps(4, 2, 4);
