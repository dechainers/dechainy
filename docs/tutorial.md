# Tutorial

This section proposes some first approach experiments with the framework, using the examples and code provided in the [examples](examples) folder.

## Creating a Pre-Defined Probe

[Reference configuration](examples/normal_probe.json)

This brief tutorial helps users to create pre-defined plugins instances, the ones which do not accept dynamic eBPF data plane code. However, in addition to this example, users can specify the additional control plane routine to be executed, but for the sake of simplicity it is presented in the following sections.

To start with, remind that a pre-defined probe needs only to specify the following parameters:

- **interface**
- **plugin_name**

With that in mind, let's run the system by providing this configuration:

```bash
docker run --rm -it --privileged --network host -v /lib/modules:/lib/modules:ro -v /usr/src:/usr/src:ro -v /etc/localtime:/etc/localtime:ro --mount type=bind,source="$(pwd)"/normal_probe.json,target=/app/startup.json s41m0n/dechainy:latest
```

Here you are! With a simple configuration you now have your Firewall injected to the desired interface.

## Creating a Custom Probe

[Reference source code](examples/src/pkt_counter)
[Reference configuration](examples/custom_probe.json)

This tutorial presents a custom probe creation, which can accept user-defined eBPF code. With the two previous references in mind, a control plane function is specified in order to execute a periodical routine. The routine, retrieves the number of incoming/outgoing packets from the eBPF programs and prints the results.

Once programmed the control plane routine, in order to correctly insert it into the configuration, the user needs to use the [formatter](../scripts/formatter.py) script to correctly encode it in a string. This operation needs to be performed also for the eBPF source code, both ingress and egress.

Finally, once specified the desired **interface** and the operational mode (XDP, XDP_DRV, XDP_SKB, XDP_HW, TC), let's inject the configuration:

```bash
docker run --rm -it --privileged --network host -v /lib/modules:/lib/modules:ro -v /usr/src:/usr/src:ro -v /etc/localtime:/etc/localtime:ro --mount type=bind,source="$(pwd)"/custom_probe.json,target=/app/startup.json s41m0n/dechainy:latest
```

In this case, other than the custom control plane routine, the metric **TOTAL_PACKETS** can be retrieved also via REST API, interacting with the controller performing a GET HTTP request to **localhost:8080/plugins/adaptmon/pkt_counter/ingress/metrics/TOTAL_PACKETS**.

```bash
~ curl http://localhost:8080/plugins/adaptmon/pkt_counter/ingress/metrics/TOTAL_PACKETS
25
```

```bash
~ curl http://localhost:8080/plugins/adaptmon/pkt_counter/ingress/metrics
{
  "TOTAL_PACKETS": "17"
}
```

In addition, the periodic routine prints a message similar to:

```bash
{'ingress': 21, 'egress': 13}
```

## Creating a Cluster

[Reference probe1 source code](examples/src/pkt_counter)
[Reference configuration](examples/cluster.json)

This tutorial presents the creation of a cluster, where two probes are created:

1. an Adaptmon pkt_counter probe, which counts both incoming and outgoing packets. No additional routine is specified
2. a Mitigator, used to insert an automatic rule (DENY 8.8.8.8) after receiving more than 10 packets, just as an example.

Differently from the probes, a cluster needs the control plane routine, which will be used as the only interaction way between its probes. In fact, as it may be noticed in the source python code, the **reaction_function** and **reaction_function_rest** functions have access to both the Adaptmon and Mitigator probes, which can be used and modified accordingly. For the sake of simplicity, this function just performs a simple interaction between the two probes, to show users the potential of such functionality.

Inject the configuration in the system:

```bash
docker run --rm -it --privileged --network host -v /lib/modules:/lib/modules:ro -v /usr/src:/usr/src:ro -v /etc/localtime:/etc/localtime:ro --mount type=bind,source="$(pwd)"/cluster.json,target=/app/startup.json s41m0n/dechainy:latest
```

From that moment on, you should periodically see a message similar to :

```bash
------------------------------
Packet Counter: Ingress(0) Egress(1)
Mitigator: {}

--------------------------
```

When reaching 10 packets, the Mitigator returns the rule that has been automatically injected:

```bash
------------------------------
Packet Counter: Ingress(20) Egress(8)
Mitigator: {
  "8.8.8.8/32": 2
}
------------------------------
```

The value of the specified entry represents the number of packets that have been mitigated after injecting the rule, in this case 2. These functionalities can also been exploited using the apposite REST API endpoint. Users just need to insert all the logic within the **reaction_function_rest** function instead of the **reaction_function**.
