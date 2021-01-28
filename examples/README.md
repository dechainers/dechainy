# Examples

This folder contains a set of examples to get started with the framework. All the JSON files are application config files, meaning that they need to be used as `startup.json` file in the root folder of this project. To achieve that, from the root folder you can type:

```bash
user@ubuntu:~/DeChain $ cp examples/<whatever_startup.json> startup.json
```

By default each configuration starts the framework in the server mode, but these files can be easily modified in order to see the differences among all the tunable parameters.

For the source code of the programmable Probes and Clusters created in these examples, please refer to the [src](src) directory.

* [create-probe_startup.json](create-probe_startup.json): this configuration is used to create a single Probe, called `pkt_counter` belonging to the Plugin Adaptmon. 
* [create-cluster_startup.json](create-cluster_startup.json): this configuration is used to create a Cluster with two probes, `pkt_counter` (Adaptmon) and `probe` (Mitigator). For the sake of simplicity, the `cp_function` of the single probe has been omitted, but it could be inserted as explained in the following example.
* [create-both_startup.json](create-both_startup.json): this configuration is used to create both a single Probe and a Cluster. While the latter is similar to the Cluster created in the previous configuration, but in addition it has specified the `cp_function` of its Adaptmon probe, the former is called `statistics_gatherer` (Adaptmon), and is an independent Probe, thus outside the Cluster.