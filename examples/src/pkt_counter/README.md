# Packet counter

Statistics Gatherer is a dynamically programmable probe (plugin Adaptmon) to simply count incoming and outgoing packets on a specific network interface.

## eBPF

The program (Ingress and Egress programs are distinct entities, but the code is the same) contains a simple eBPF Array map with one entry, which is incremented every time a packet is analysed.

No advanced methods have been implemented. This is just a reference program for the examples, to get started as soon as possible.

## Control Plane

The Control Plane periodically retrieves the number of packets from the Ingress and Egress programs, and prints them. The eBPF maps are not emptied, thus the value is always incrementing.
