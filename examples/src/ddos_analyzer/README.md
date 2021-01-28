# DDoS Analyzer

DDoS Analyzer is a dynamically programmable probe (plugin Adaptmon) to extract features from network traffic packets on a specific network interface, and feed them into a Convolutional Neural Network, in order to predict possible ongoing cyber attacks.

## eBPF

The eBPF programs, which are invoked for each passing packet, are composed by two main maps:

* SESSIONS_TRACKED_DDOS: an Hash map containing the session identifier of each connection and some parameters, like the number of registered packets and the address of the heuristically computed server
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

Obviously, the features are not all active at the same time, since different protocols extracts different data.

Whenever a new packet is analyzed, the programs checks whether the current session identifying the packet has already registered a maximum amount of packets, to avoid that only a specific flow fills the queue. If the packet can be registered, then, depending on the protocol used, the set of features is extracted.

## Control Plane

The Control Plane periodically atomically reads both the SESSIONS_TRACKED_DDOS and PACKETS_BUFFER maps, and aggregates results per-flow. It pads the results and normalizes them in order to produce the correct data to fill the neural network. Once the prediction is performed, each flow is tagged with the result (malicious/benign) and returned to the user.

## Acknowledgement

A special thanks goes to all the author of [this paper](https://www.researchgate.net/publication/339059257_Lucid_A_Practical_Lightweight_Deep_Learning_Solution_for_DDoS_Attack_Detection) ([GitHub repo](https://github.com/doriguzzi/lucid-ddos)), my current colleagues, for their incredibly efficient finding I tried to re-implement as example in this framework.