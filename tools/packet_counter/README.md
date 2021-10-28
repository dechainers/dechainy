# Packet counter

Statistics Gatherer is a dynamically programmable probe (plugin Adaptmon) to simply count incoming and outgoing packets on a specific network interface.

## eBPF

The [program](ebpf.c) (Ingress and Egress programs are distinct entities, but the code is the same) contains a simple eBPF Array map with one entry, which is incremented every time a packet is analysed.

No advanced methods have been implemented. This is just a reference program for the examples, to get started as soon as possible.

## Control Plane

The [Control Plane](cp.py) periodically retrieves the number of packets from the Ingress and Egress programs, and prints them. The eBPF maps are not emptied, thus the value is always incrementing.

## Cluster

[This](cluster_cp.py) is an example of a cluster with multiple probes that interact. It is composed by:

* Packet counter, to periodically retrieve incoming and outgoing number of packets
* Mitigator, insert a dumb rule (block 8.8.8.8) once reached a certain treshold of incoming packets.

This example is just to give an idea about how to code a control plane function and how to access probes within a cluster.
