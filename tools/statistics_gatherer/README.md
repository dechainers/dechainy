# Statistics Gatherer

Statistics Gatherer is a dynamically programmable probe (plugin Adaptmon) to gather statistics from the traffic on a specific network interface.

## eBPF

In order to efficiently gather statistics without affecting the system throughput. an efficient swappable PER-CPU map has been used. This allows us to:

* perform an independent packet analysis on each CPU
* read atomically data by substituting the current used map with a fictitious one, which will be alternatively read/filled.

Each packet belonging to a specific session (max. 10000 session, can be modified) the following values of the eBPF map values are updated:

* n_packets: number of packets on one direction
* n_packets_reverse: number of packets on opposite direction
* n_bytes: total bytes on one direction
* n_bytes_reverse: total bytes on opposite direction
* start_timestamp: connection begin timestamp
* alive_timestamp: last message received timestamp
* server_ip: the IP of the server
* method: the method used to determine the server

These values will be later post-processed by the control Plane, as described in the following section.

## Control Plane

Periodically, the control plane swaps the current eBPF map and reads the gathered data from the map that has been swapped-out, meaning that it is not active anymore.
For each session, it aggregates each PER-CPU data into a unique entry, by:

* summing up n_packets, n_packets_reverse, n_bits, n_bits_reverse
* saving the value for method != 0, start_timestamp != 0, and server_ip !=0
* storing the latest alive_timestamp measured

Once aggregated data, the control plane computes and prints all the following values:

* the last timestamp belonging to the connection
* the method used to identify the server
* the number of packets for the Client
* the number of packets for the Server
* the number of bits for the Client
* the number of bits for the Server
* the duration of the connection (the measure is in nanoseconds)
* the client packets per second (pkts/sec)
* the server packets per second (pkts/sec)
* the client bits per second (bits/sec)
* the server bits per second (bits/sec)
* the client bits over packets (bits/pkts)
* the server bits over packets (bits/pkts)
* the server packets over the client packets (pkts/pkts)
* the server bits over the client bits (bits/bits)
