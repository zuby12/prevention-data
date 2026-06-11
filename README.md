Eclipse Defense Evaluation Framework (Geth-based Testbed)
Overview

This project is a research testbed for evaluating eclipse attack scenarios and Moving Target Defense (MTD) strategies in a Geth-based peer-to-peer blockchain network.

It provides a controlled environment to simulate different network conditions, adversarial behaviors, and defense mechanisms, and to measure their impact on network security and performance.

Features
Geth-based distributed network orchestration
Eclipse attack and network stress simulations
MTD strategies:
Fixed peer shuffling
Random peer replacement
Adaptive risk-based defense
RPC and transaction load generation
Network churn and peer manipulation scenarios
Automated metrics collection and analysis


Experiments generate CSV logs and summaries, including:

Peer statistics
Trust and entropy metrics
Defense success rate (DSR)
Transaction propagation delay
Attack impact measurements


Run experiments:

python eclipse_updated.py --run baseline,fixed,random,adaptive --duration 300
