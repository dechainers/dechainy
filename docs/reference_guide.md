# Reference guide

This section covers most of the basic operations with the framework, illustrating its most important features. For a more detailed and complete guide, please refer also to the [api](api) guide.

1. [Controller](#controller)
2. [EbpfCompiler](#ebpfcompiler)
3. [Enhanced Map Features](#enhanced-map-features)
4. [Plugins and Probes](#plugins-and-probes)
5. [eBPF Helpers](#ebpf-helpers)

## Controller

The Controller is the main component, responsible for creating, modifying, and destroying probes and plugin. This component performs all the operations safely, managing concurrent accesses, to avoid mistakes and incoherency. Moreover, it is equipped with a watchdog task that monitoring actions on the plugin directory, to keep the system (i.e. plugins and probes) synchronised. It is not possible in fact to have probes belonging to a deleted plugin.

Among all the other operations performed, the controller adds two additional functionalities:

1. Enables the eBPF programs logging
2. Enables the forward of packets from the data plane to the control plane

Those functionalities require the destination probe to implement the requested one, especially for managing a packet in control plane, otherwise nothing happens (no default actions are registered).

## EbpfCompiler

This component is responsible for compiling, injecting and removing eBPF programs in the various interfaces and managing the service program chain. It should always be used only from the Controller component, despite those cases where a Probe itself wants to autopatch its code for a specific hook.

This class is a Singleton, as having multiple instances of this component managing network interfaces could result dangerous for the system, leading it to an unsafe state.

### Enhanced Map Features

Declarable with `__attributes__(())` after the map declaration, values inside the brackets can be:

1. **SWAP**: the most complex features that requires the access to the map to be atomic. To do so, a parallel program with fictitious maps is compiled and alternatively substituted to the original one.
2. **EMPTY**: this teaches the probe to erase the map content every time it is required and returned to the user.
3. **EXPORT**: this feature allows exporting the map content outside the application. By default, it would not be possible, in order to preserve sensible data.

**It is not possible** to declare between many `ifdef` the map reusing the same name, but with different features. An example:

```bash
#ifdef ATTEMPT
BPF_TABLE("array", int, int, MY_NAME, 1)__attributes__((SWAP));
#else
BPF_TABLE("array", int, int, MY_NAME, 1)__attributes__((EXPORT));
#endif
```

This leads the compiler to an unknown behaviour, enabling both the two features even though not required.

## Plugins and Probes

Plugins are the keystones of the framework. They represent entire modules and potential instantiable probes to be injected as monitoring programs in the system, and running an entire control plane logic depending on the needs. Each plugin must have at least one hook between *ingress* and *egress*, otherwise its functioning would be non-sense. Moreover, they exposes APIs that can be used to interact with, other than standard functions provided by the framework.

A plugin is basically a directory, containing the following files:

1. ``__init__.py``: the main file where also the plugin class is defined. The class must
    1. Inherit from `Probe`, the class defined [here](../dechainy/plugins/__init__.py)
    2. Be a dataclass (`@dataclass`)
    3. Have at least one of the source codes available presented in the next point (2).
2. `ebpf.c` or `ingress.c` or `egress.c`: in case `ebpf.c` is provided, that source code can be used for both the hooks. Otherwise, their apposite source codes will be used to load the program.
3. `routes.py` (Optional): for registering ad-hoc new REST API endpoints.

A probe is an instance of a Plugin, that specifies the target to which attach the eBPF program, additional custom configurations and functions.

For further information, check the provided plugins (for instance, visit [dechainy_plugin_firewall](https://github.com/dechainers/dechainy_plugin_firewall) and [dechainy_web](https://github.com/dechainers/dechainy_web).

## eBPF Helpers

A list of eBPF helpers introduced in the framwork, among all the other ones offered by BCC, is provided below.

Provided directly by eBPF source [helpers](../dechainy/sourcebpf/helpers.h):

1. ``IPPROTO_TCP``, ``IPPROTO_UDP``, ``IPPROTO_ICMP``, ``ETH_P_IP``, ``ECHO_REQUEST``, ``ECHO_REPLY``: some of the many protocols' values according to the standard.
2. ``struct eth_hdr``, ``struct iphdr``, ``struct tcphdr``, ``struct udphdr``, ``struct icmphdr``: some of the various packet headers' structures according to the standard.
3. ``struct pkt_metadata``: structure containing metadata about the current packet.
4. ``struct lpm_key``: structure to represent an *lpm_key* if needed.
5. ``BPF_PERF(ATTR, NAME)``, ``BPF_PERF_SHARED(ATTR, NAME)``: helpers to declare a perf buffer with additional attributes (e.g., *extern*).
6. ``BPF_PERF("extern", log_buffer)``: log buffer to send messaged to be logged to the control plane.
7. ``BPF_PERF("extern", control_plane)``: buffer to forward packets from data plane to control plane when needed.
8. ``static __always_inline int pkt_to_controller(struct CTXTYPE *ctx, struct pkt_metadata *md)``: implement the message forward phase of the control_plane buffer.
9. ``u64 get_time_epoch(struct CTXTYPE *ctx)``: return the timestamp of the current time in Unix time epoch format.
10. ``static __always_inline int first_bit_set_pos(u64 x)``: return the position of the first bit set in the provided number.

Added by EbpfCompiler while [compiling](../dechainy/ebpf.py):

1. `dp_log(LOG_LEVEL, STRING, param1, ..param4)`: helper that implements the usage of the logging buffer to log messages in control plane from an eBPF program. A maximum amount of 4 parameters can be forwarded, and they must be used (i.e., formatted in the message string with apposite operators, like `%d`)
2. `REDIRECT(interface)`: helper to redirect the current packet to the specified interface, that is controlled and substituted with its ID by the compiler.