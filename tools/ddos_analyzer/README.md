# DDoS Analyzer

DDoS Analyzer is a dynamically programmable probe (plugin Adaptmon) to extract features from network traffic packets on a specific network interface, and feed them into a Convolutional Neural Network, in order to predict possible ongoing cyberattacks.

## eBPF

The eBPF programs, which are invoked for each passing packet, are composed by two main maps:

* SESSIONS_TRACKED_DDOS: a Hash map containing the session identifier of each connection and some parameters, like the number of registered packets and the address of the heuristically computed server
* PACKETS_BUFFER: a fixed-size Queue which contains all the accepted packets, filtered by their features.

A complete list of features extracted is:

* timestamp: timestamp of when the packet has been analyzed
* length: the length of the Layer3 packet
* ipFlagsFrag: the IP field Flags+FragmentOffset (16 bytes in total, 3 for flags)
* tcpLen: the length of the TCP packet
* tcpAck: the acknowledgment number of TCP
* tcpFlags: the flags specified in the TCP header
* tcpWin: the size of the TCP window
* udpSize: the size of the UDP packet
* icmpType: the type of the ICMP packet

Obviously, the features are not all active at the same time, since different protocols extracts different data. Features can be activated or deactivated by inserting specific cflags in the probe configuration (see [ebpf.c](ebpf.c) for possible values).

Whenever a new packet is analyzed, the programs checks whether the current session identifying the packet has already registered a maximum amount of packets, to avoid that only a specific flow fills the queue. If the packet can be registered, then, depending on the protocol used, the set of features is extracted.

## Control Plane

The control plane periodically atomically reads the PACKETS_BUFFER map and erase the content of SESSIONS_TRACKED_DDOS, in order to be able to start monitoring new sessions once the program has been swapped back. Then, asynchronously manipulate and trasform such data, in order to feed the neural network provided. More in details:

* Packets are grouped in arrays for each flow
* Packets' values are normalized
* If needed, the arrays are padded in order to fill the number of packets per flow required by the network

## Neural Network model

A neural network model can be provided in the configuration of the probe as:

* text: using the [formatter.py](../../scripts/formatter.py) script
* path: the path to the model

The probe configuration must be as follows:

```bash
{
    "probes": [
        {
            ...
            "ingress": ...,
            "egress": ...,
            "cp_function": ...,
            "extra": {
                "model": <put here the value>
            }
        }
    ]
}
```

## Acknowledgment

A special thanks goes to all the author of [this paper](https://www.researchgate.net/publication/339059257_Lucid_A_Practical_Lightweight_Deep_Learning_Solution_for_DDoS_Attack_Detection) ([GitHub repo](https://github.com/doriguzzi/lucid-ddos)), my current colleagues, for their incredibly efficient finding I tried to re-implement as example in this framework.
