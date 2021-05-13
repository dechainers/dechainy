# Examples

This folder contains a set of examples to get started with the framework. All the JSON files are application config files, meaning that they need to be used as `startup.json` file in the root folder of this project. To achieve that, from the root folder you can type:

```bash
user@ubuntu:~/DeChainy $ cp examples/<whatever_startup.json> startup.json
```

By default, each configuration starts the framework in the server mode, but these files can be easily modified in order to see the differences among all the tunable parameters.

For the source code of the programmable Probes and Clusters created in these examples, please refer to the [src](src) directory.

* [normal_probe.json](normal_probe.json): this configuration is used to create a single non-programmable Probe, in this case a Firewall instance.
* [custom_probe.json](custom_probe.json): this configuration is used to create a single programmable Probe Adaptmon.
* [cluster.json](cluster.json): this configuration is used to create a Cluster with two probes, `pkt_counter` (Adaptmon) and `probe` (Mitigator). The control plane function simply inserts a dumb rule whenever the interface has received more than 10 packets.
