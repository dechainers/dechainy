# Tutorial

This section proposes some first approach experiments with the framework.

## Creating a Non-Programmable (Pre-defined) Probe

**Configuration** (startup.json):

```json
{
  "probes": [
    {
      "plugin": "firewall",
      "name": "simple_fw",
      "mode": "XDP",
      "interface": "wlp0s20f3"
    }
  ],
  "server": {
    "address": "0.0.0.0",
    "port": 8080
  }
}
```

This brief tutorial helps users to create pre-defined plugins instances, the ones which do not accept dynamic eBPF data plane code. However, in addition to this example, users can specify the additional control plane routine to be executed, but for the sake of simplicity it is presented in the following sections.

To start with, remind that a pre-defined probe needs only to specify the following parameters:

- **interface**
- **plugin_name**

With that in mind, let's run the system by providing this configuration:

```bash
docker run --rm -it --privileged --network host -v /lib/modules:/lib/modules:ro -v /usr/src:/usr/src:ro -v /etc/localtime:/etc/localtime:ro --mount type=bind,source="$(pwd)"/startup.json,target=/app/startup.json s41m0n/dechainy:latest
```

Here you are! With a simple configuration, you now have your Firewall injected to the desired interface.

## Creating a Programmable (Custom) Probe

[Reference source code](../tools/packet_counter)

**Configuration** (startup.json):

```json
{
  "probes": [
    {
      "plugin": "adaptmon",
      "name": "pkt_counter",
      "mode": "XDP",
      "interface": "wlp0s20f3",
      "ingress": "// Copyright 2020 DeChainy\n//\n// Licensed under the Apache License, Version 2.0 (the \"License\");\n// you may not use this file except in compliance with the License.\n// You may obtain a copy of the License at\n//\n//    http://www.apache.org/licenses/LICENSE-2.0\n//\n// Unless required by applicable law or agreed to in writing, software\n// distributed under the License is distributed on an \"AS IS\" BASIS,\n// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n// See the License for the specific language governing permissions and\n// limitations under the License.\nBPF_TABLE(\"array\", int, uint64_t, TOTAL_PACKETS, 1)__attributes__((EXPORT));\n\nstatic __always_inline\nint handler(struct CTXTYPE *ctx, struct pkt_metadata *md) {\n    void *data = (void *) (long) ctx->data;\n    void *data_end = (void *) (long) ctx->data_end;\n\n   /*Parsing L2*/\n    struct eth_hdr *ethernet = data;\n    if (data + sizeof(*ethernet) > data_end)\n        return PASS;\n\n    if (ethernet->proto != bpf_htons(ETH_P_IP))\n        return PASS;\n\n    /*Parsing L3*/\n    struct iphdr *ip = data + sizeof(struct eth_hdr);\n    if (data + sizeof(struct eth_hdr) + sizeof(*ip) > data_end)\n        return PASS;\n\n    TOTAL_PACKETS.increment(0);\n\n    return PASS;\n}",
      "egress": "// Copyright 2020 DeChainy\n//\n// Licensed under the Apache License, Version 2.0 (the \"License\");\n// you may not use this file except in compliance with the License.\n// You may obtain a copy of the License at\n//\n//    http://www.apache.org/licenses/LICENSE-2.0\n//\n// Unless required by applicable law or agreed to in writing, software\n// distributed under the License is distributed on an \"AS IS\" BASIS,\n// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n// See the License for the specific language governing permissions and\n// limitations under the License.\nBPF_TABLE(\"array\", int, uint64_t, TOTAL_PACKETS, 1)__attributes__((EXPORT));\n\nstatic __always_inline\nint handler(struct CTXTYPE *ctx, struct pkt_metadata *md) {\n    void *data = (void *) (long) ctx->data;\n    void *data_end = (void *) (long) ctx->data_end;\n\n   /*Parsing L2*/\n    struct eth_hdr *ethernet = data;\n    if (data + sizeof(*ethernet) > data_end)\n        return PASS;\n\n    if (ethernet->proto != bpf_htons(ETH_P_IP))\n        return PASS;\n\n    /*Parsing L3*/\n    struct iphdr *ip = data + sizeof(struct eth_hdr);\n    if (data + sizeof(struct eth_hdr) + sizeof(*ip) > data_end)\n        return PASS;\n\n    TOTAL_PACKETS.increment(0);\n\n    return PASS;\n}",
      "cp_function": "# Copyright 2020 DeChainy\n#\n# Licensed under the Apache License, Version 2.0 (the \"License\");\n# you may not use this file except in compliance with the License.\n# You may obtain a copy of the License at\n#\n#    http://www.apache.org/licenses/LICENSE-2.0\n#\n# Unless required by applicable law or agreed to in writing, software\n# distributed under the License is distributed on an \"AS IS\" BASIS,\n# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n# See the License for the specific language governing permissions and\n# limitations under the License.\nfrom dechainy.plugins import Plugin\n\n\ndef reaction_function_rest(probe: Plugin):\n    return {'ingress': probe[\"ingress\"]['TOTAL_PACKETS'][0].value,\n            'egress': probe[\"egress\"]['TOTAL_PACKETS'][0].value}\n\n\ndef reaction_function(probe: Plugin):\n    print(reaction_function_rest(probe), flush=True)\n"
    }
  ],
  "server": {
    "address": "0.0.0.0",
    "port": 8080
  }
}
```

This tutorial presents a custom probe creation, which can accept user-defined eBPF code. With the two previous references in mind, a control plane function is specified in order to execute a periodical routine. The routine, retrieves the number of incoming/outgoing packets from the eBPF programs and prints the results.

Once programmed the control plane routine, in order to correctly insert it into the configuration, the user needs to use the [formatter](../scripts/formatter.py) script to correctly encode it in a string. This operation needs to be performed also for the eBPF source code, both ingress and egress.

Finally, once specified the desired **interface** and the operational mode (XDP, XDP_DRV, XDP_SKB, XDP_HW, TC), let's inject the configuration:

```bash
docker run --rm -it --privileged --network host -v /lib/modules:/lib/modules:ro -v /usr/src:/usr/src:ro -v /etc/localtime:/etc/localtime:ro --mount type=bind,source="$(pwd)"/startup.json,target=/app/startup.json s41m0n/dechainy:latest
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

[Reference source code](../tools/packet_counter)

```json
{
  "clusters": [
    {
      "name": "cluster1",
      "cp_function": "# Copyright 2020 DeChainy\n#\n# Licensed under the Apache License, Version 2.0 (the \"License\");\n# you may not use this file except in compliance with the License.\n# You may obtain a copy of the License at\n#\n#    http://www.apache.org/licenses/LICENSE-2.0\n#\n# Unless required by applicable law or agreed to in writing, software\n# distributed under the License is distributed on an \"AS IS\" BASIS,\n# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n# See the License for the specific language governing permissions and\n# limitations under the License.\nimport json\n\nfrom dechainy.configurations import MitigatorRule\nfrom dechainy.plugins import Cluster\nfrom dechainy.utility import ipv4_to_string\n\ncounter: int = 0\n\n\ndef reaction_function_rest(cluster: Cluster):\n    global counter\n    counter += 1\n\n    cnt_ingress = cluster['adaptmon']['pkt_counter'][\"ingress\"]['TOTAL_PACKETS'][0].value\n    cnt_egress = cluster['adaptmon']['pkt_counter'][\"egress\"]['TOTAL_PACKETS'][0].value\n    rules = {}\n    # NB: it is possible to call the probe specific control plane method instead of directly\n    #     accessing the map. Thus, pay attention to what you do.\n    for key, cnt in cluster['mitigator']['probe'][\"ingress\"]['BLACKLISTED_IPS'].items():\n        rules[f\"{ipv4_to_string(key.ip)}/{key.netmask_len}\"] = cnt.value\n\n    return {\n        'pkt_ingress': cnt_ingress,\n        'pkt_egress': cnt_egress,\n        'mitigator_rules': rules}\n\n\ndef reaction_function(cluster: Cluster):\n    global counter\n\n    ret = reaction_function_rest(cluster)\n\n    print('------------------------------\\n'\n          f'Packet Counter: Ingress({ret[\"pkt_ingress\"]}) Egress({ret[\"pkt_egress\"]})\\n'\n          f'Mitigator: {json.dumps(ret[\"mitigator_rules\"], indent=2)}')\n\n    if ret['pkt_ingress'] > 10 and not ret['mitigator_rules']:\n        print('Filling map with rule')\n        # NB: it is possible to directly access the eBPF map, but then the rule would not be pushed into\n        #     the Python class. Thus, pay attention to what you do.\n        cluster[\"mitigator\"][\"probe\"].insert(MitigatorRule({\"netmask\": 32, \"ip\": \"8.8.8.8\"}))\n    print('', flush=True)\n",
      "probes": [
        {
          "plugin": "adaptmon",
          "name": "pkt_counter",
          "mode": "XDP",
          "interface": "wlp0s20f3",
          "ingress": "// Copyright 2020 DeChainy\n//\n// Licensed under the Apache License, Version 2.0 (the \"License\");\n// you may not use this file except in compliance with the License.\n// You may obtain a copy of the License at\n//\n//    http://www.apache.org/licenses/LICENSE-2.0\n//\n// Unless required by applicable law or agreed to in writing, software\n// distributed under the License is distributed on an \"AS IS\" BASIS,\n// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n// See the License for the specific language governing permissions and\n// limitations under the License.\nBPF_TABLE(\"array\", int, uint64_t, TOTAL_PACKETS, 1);\n\nstatic __always_inline\nint handler(struct CTXTYPE *ctx, struct pkt_metadata *md) {\n    void *data = (void *) (long) ctx->data;\n    void *data_end = (void *) (long) ctx->data_end;\n\n   /*Parsing L2*/\n    struct eth_hdr *ethernet = data;\n    if (data + sizeof(*ethernet) > data_end)\n        return PASS;\n\n    if (ethernet->proto != bpf_htons(ETH_P_IP))\n        return PASS;\n\n    /*Parsing L3*/\n    struct iphdr *ip = data + sizeof(struct eth_hdr);\n    if (data + sizeof(struct eth_hdr) + sizeof(*ip) > data_end)\n        return PASS;\n\n    TOTAL_PACKETS.increment(0);\n\n    return PASS;\n}",
          "egress": "// Copyright 2020 DeChainy\n//\n// Licensed under the Apache License, Version 2.0 (the \"License\");\n// you may not use this file except in compliance with the License.\n// You may obtain a copy of the License at\n//\n//    http://www.apache.org/licenses/LICENSE-2.0\n//\n// Unless required by applicable law or agreed to in writing, software\n// distributed under the License is distributed on an \"AS IS\" BASIS,\n// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n// See the License for the specific language governing permissions and\n// limitations under the License.\nBPF_TABLE(\"array\", int, uint64_t, TOTAL_PACKETS, 1);\n\nstatic __always_inline\nint handler(struct CTXTYPE *ctx, struct pkt_metadata *md) {\n    void *data = (void *) (long) ctx->data;\n    void *data_end = (void *) (long) ctx->data_end;\n\n   /*Parsing L2*/\n    struct eth_hdr *ethernet = data;\n    if (data + sizeof(*ethernet) > data_end)\n        return PASS;\n\n    if (ethernet->proto != bpf_htons(ETH_P_IP))\n        return PASS;\n\n    /*Parsing L3*/\n    struct iphdr *ip = data + sizeof(struct eth_hdr);\n    if (data + sizeof(struct eth_hdr) + sizeof(*ip) > data_end)\n        return PASS;\n\n    TOTAL_PACKETS.increment(0);\n\n    return PASS;\n}"
        },
        {
          "plugin": "mitigator",
          "name": "probe",
          "mode": "XDP",
          "interface": "wlp0s20f3"
        }
      ]
    }
  ],
  "server": {
    "address": "0.0.0.0",
    "port": 8080
  }
}
```

This tutorial presents the creation of a cluster, where two probes are created:

1. an Adaptmon pkt_counter probe, which counts both incoming and outgoing packets. No additional routine is specified
2. a Mitigator, used to insert an automatic rule (DENY 8.8.8.8) after receiving more than 10 packets, just as an example.

Differently from the probes, a cluster needs the control plane routine, which will be used as the only interaction way between its probes. In fact, as it may be noticed in the source python code, the **reaction_function** and **reaction_function_rest** functions have access to both the Adaptmon and Mitigator probes, which can be used and modified accordingly. For the sake of simplicity, this function just performs a simple interaction between the two probes, to show users the potential of such functionality.

Inject the configuration in the system:

```bash
docker run --rm -it --privileged --network host -v /lib/modules:/lib/modules:ro -v /usr/src:/usr/src:ro -v /etc/localtime:/etc/localtime:ro --mount type=bind,source="$(pwd)"/startup.json,target=/app/startup.json s41m0n/dechainy:latest
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
