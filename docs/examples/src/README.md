# Examples

This folder contains the source code of the programs used within the example configurations:

* [pkt_counter](pkt_counter): Adaptmon probe to count incoming and outgoing packets from a specific network interface (used in the examples).
* [cluster_cp.py](cluster_cp.py): the control Plane of the Cluster, which periodically checks if the n° incoming packets is greater than a threshold and inserts a rule in the Mitigator Plugin to block incoming traffic from 8.8.8.8, a dumb rule just to prove that components can cooperate and the Mitigator can effectively block traffic (used in the examples).
