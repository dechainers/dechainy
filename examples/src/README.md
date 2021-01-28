## Examples Source folder

This folder (and all its sub-folders) contains many examples of programmable Probes and Cluster, which have also been used in the examples. Each program has its own description, so you may want to check out the following folders:

* [pkt_counter](pkt_counter): Adaptmon probe to count incoming and outgoing packets from a specific network interface (used in the examples).
* [statistics_gatherer](statistics_gatherer): Adaptmon probe to gather statistics (n° packets, n° bits, etc.) concerning incoming and outgoing traffic from a specific network interface (used in the examples).
* [ddos_analyzer](ddos_analyzer): Adaptmon probe to extract features from incoming and outgoing packets, in order to feed a Neural Network, which predicts possible cyber attacks, following the model presented in the [Lucid paper](https://github.com/doriguzzi/lucid-ddos).
---
* [cluster_cp.py](cluster_cp.py): the Control Plane of the Cluster, which periodically checks if the n° incoming packets is greater than a threshold and inserts a rule in the Mitigator Plugin to block incoming traffic from 8.8.8.8, a dumb rule just to prove that components can cooperate and the Mitigator can effectively block traffic (used in the examples).