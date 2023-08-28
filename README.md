# External ZKML actor
This is a proof-of-concept implementation of a zero-knowledge proof application designed for Gear-powered blockchains.

> **Note**
Please be aware that this work might contain inaccuracies, suboptimal optimizations, and critical security bugs. The solutions employed are absolutely not recommended for production use, as they are still in heavy development.

# Overview
This implementation offers the capability to offload the resource-intensive computations from the blockchain while ensuring their integrity. As an illustrative example, we demonstrate the evaluation of the MNIST machine learning model. This is achieved by generating zero-knowledge proofs of computations and subsequently verifying them on-chain.

# Workflow

The process of employing zero-knowledge proofs for computations involves four key participants: `Initializer`, `User`, `zk-smart-contract` and `Prover`.

1. `Initializer`: This participant is responsible for deploying the `zk-smart-contract` onto the blockchain and initializing its parameters. During initialization, the structure of the machine learning model is defined, setting the stage for subsequent interactions.

2. `User`: Users of the system interact with the `zk-smart-contract` by submitting their input data, which is intended for processing by the machine learning model. This step demonstrates how external parties can seamlessly engage with the blockchain without directly executing computationally intensive operations.

3. `Prover`: The prover retrieves this input from the `zk-smart-contract`, conducts an evaluation of the machine learning model, and generates a zero-knowledge proof that attests to the validity of the computation. The resulting output of the machine learning model, along with the zero-knowledge proof, is then submitted back to the `zk-smart-contract`.

4. `User Verification`: Users initiate a verification process by interacting with the `zk-smart-contract`. The `zk-smart-contract` orchestrates the verification of the zero-knowledge proof, independently confirming the accuracy of the computation without exposing sensitive data.

5. `Verification Outcome`: Once the verification process is completed within the `zk-smart-contract`, the user is informed of the verification outcome.