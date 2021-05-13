# Reference guide

This section covers most of the basic operations with the framework, illustrating its most important features. For a more detailed and complete guide, please refer also to the [api](api) guide.

## Contents

- [Operational Modes](#1-operational-modes)
- [Startup Configuration File](#2-startup)
- [Plugins](#3-plugins)
  - [Programmable Data Plane](#3.1-programmable)
    - [Adaptmon](#3.1.1-adaptmon)
  - [Non-programmable](#3.2-non-programmable)
    - [Mitigator](#3.2.1-mitigator)
    - [Firewall](#3.2.2-firewall)
- [Clusters](#4-clusters)
- [Control Plane Functions](#5-control-plane-functions)
- [Hands-on](#6-hands-on)

## 1. Operational Modes

The framework can work in two different operational modes:

- Rest API server, a.k.a. server mode
- Serverless, a.k.a. script mode

The operational mode is decided at startup time, if a configuration ([**startup.json**](#2-startup)) has been provided. When working in server mode, the system offers a REST API server built over Flask, which can accept HTTP request to interact with (e.g., creation/deletion of probes, clusters, retrieval of configurations). In the serverless mode, the framework can be used within a local script (Python or whatever) to interact with, like any traditional eBPF program written within BCC. However, the advantage of using DeChainy is the automatic Service Program Chain creation, which allow you to instantiate and attach multiple probes to the same network interface. Consequently, the framework automatically executed the monitoring code on the incoming/outgoing traffic (in-out different policies are supported).

## 2. Startup

The startup file (**startup.json**) is a very important configuration that will be read by the framework in order to create the desired probes, and start the REST server if specified. When providing such configuration, the file needs to be located at the root of the project, in order to be correctly parsed.

According to the [API documentation](api/configurations.md):

`AppConfig:`
:   Class to represent the startup configuration in a startup.json file.
    
    Attributes:
        plugins (List[str]): List of plugins to enable. Default [] (ALL).
        cluster (List[ClusterConfig]): List of clusters to create at startup. Default [].
        probes (List[ProbeConfig]): List of probes to create at startup. Default [].
        server (ServerConfig): Server configuration, if any. Default None.
        custom_cp (bool): True if the system can accept custom control plane code, False otherwise. Default True.
        log_level (int): Log level for the entire application. Default INFO.

Basically, the configuration can contain:

- the list of plugins to enable (e.g. ["adaptmon”, "mitigator"]);
- the list of clusters to create
- the list of probes to create (instance of Plugins)
- the configuration for the Server (e.g., address and port)
- the possibility to accept dynamic user-define control plane routines. When disabled, clusters are not available, since they would not make sense
- the log level of the entire framework (check [DPLogLevel](api/configurations.md))

This configuration is optional. If not provided, the framework will automatically configure to work with all the Plugins active, and a server will be started at **localhost:8080**. From that moment on, the creation of probes and clusters need to be managed via REST API.

## 3. Plugins

The core of this framework are the possible Plugins that can be used. Everytime an instance of a plugin is created, its relative eBPF code and control plane code (if required) are injeted in the system, allowing to interact users with the probe both via REST API or Python scripts. There are two different types of plugins:

1. Programmable
2. Non-Programmable

While all the Plugins can accept control plane routines to be periodically executed, the main difference between the two types is that the Programmable ones accept also eBPF code to be injected into the system, differently from the Non-Programmable ones that have pre-defined source code hosted in the [sourcebpf](../dechainy/sourcebpf) folder.

To create an instance of the desired plugin, the system accepts an HTTP request if started in server mode, or the Controller class exposes the same functions that can be called within a script.

Independently by the type of the Plugin, each one accepts a control plane routine that, differently from the traditional interactions defined within the source files, is periodically executed. This functionality is not safe, since the source Python code provided is not checked, thus malicious instructions can be executed. However, this functionality can be disabled by specifying in the startup configuration the proper option. However, it can be useful especially when using local programs (serverless mode) that need to interact with the system (e.g., write to files monitoring results), like every BCC tool. While being superfluous when dealing with single probes, this functionality is extremely useful when using clusters. In fact, as later explained, the advantage of using clusters is that they offer the possibility to directly interact with other probes, without passing through standard Controller functions.

A Plugin configuration can accept all the following parameters:

`ProbeConfig(obj: dict = None)`
:   Class to represent a Probe configuration.
    
    Attributes:
        interface (str): The interface to which attach the program
        mode (int): The mode to insert the program (XDP or TC). Default TC.
        flags (int): Flags for the mode, automatically computed.
        time_window (float): Periodic time to locally call the Controlplane function, if any. Default 10.
        ingress (str): Code for the ingress hook. Default None.
        egress (str): Code for the egress hook. Default None.
        cp_function (str): The Control plane routine to be periodically executed if needed. Default "".
        cflags (List[str]): List of Cflags to be used while compiling programs. Default [].
        files (Dict[str, str]): Dictionary containing additional files for the probe. Default {}.
        debug (bool): True if the probe must be inserted in debug mode. Default False.
        redirect(str): The name of the interface you want packets to be redirect as default action, else None
        plugin_name (str): The name of the plugin. Default None. (Set by Controller)
        name (str): The name of the probe. Default None. (Set by Controller)

The only parameter that is always needed in this configuration is the **interface**, otherwise the system does not know which interface where to attack the program. However, depending on the probe programmability, it may accept other attributes, like the **ingress** or **egress** eBPF code, the custom control plane routine **cp_function** and more. When starting the system in the serverless mode, it is requested also to provide the name of the plugin and the name.

Other fields like **files** are used when the control plane routine needs to access files or information sent within the probe configuration (e.g., neural network models, and more).

The **redirect** option is used when the probe needs to forward traffic to another specific interface, after successfully analysing it.

An example of a probe control plane function can be retrieved [here](examples/src/pkt_counter/cp.py).

### 3.1 Programmable

As previously stated, these probes can accept dynamic data plane code (eBPF programs) that will be injected into the system, differently from the Non-Programmable ones that have their own eBPF source pre-defined. The advantage of this type of Plugins, is the ability to offer to users a more personalized network monitoring, called opportunistic network monitoring. In fact, the user can change his/her desired monitoring program at runtime, without worrying about the entire Service Chain stability.

When accepting a user-defined monitoring program, while the eBPF code can be validated by the apposite compiler and validator, the control plane functions can be either left up to the user, which can inject his/her own Python routine, or a general adaptive component needs to be coded, in order to handle and supervise all the possible monitoring scenarios. However, since accepting dynamic routines can be disabled in the startup configuration, these programmable plugins offer a series of standard API thanks to it is possible to retrieve the desired metric, if specified. In fact, the result of the monitoring can be viewed as a series of metrics to be exported outside the system.

A metric is characterized by:

- a name
- the name of the underlying eBPF map
- additional features specified in the eBPF map declaration (eBPF source code)

The additional features are inserted at the end of each map declaration, specifying **\_\_attributes\_\_\(\(\)\)**, which can contain inside the brackets:

- EMPTY: when retrieving this metric, the underlying eBPF map needs to be emptied, zeroing its content. This allows a time-window network monitoring, instead of an incremental one.
- EXPORT: the eBPF map representing the metric needs to be exported outside
- SWAP: the eBPF metric needs to be atomically retrieved. This is the most comples concept within these features: basically, to keep coherent data when the control plane retrieves data from the eBPF program while the Data plane function keeps filling the map, we propose this advanced functionality, which allow users to consistently and safely retrieve all the metrics defined. Instead of a swappable dual-map approach, this feature is implemented as a swappable dual-programs approach, which results to have less latency swap interval, thus it does not affect networking performance. However, users must be aware that when activating this feature, the metric cannot represent the full state of the monitoring, as the two maps may contain different snapshot of the traffic, and aggregates between the two maps are not supported. Thus, if the user wants to perform an over-time network monitoring, this feature is not probably the best choice. On the other hand, if some metrics need to be incremental and others do not, this functionality perfectly fits your needs, allowing you to keep incremental eBPF maps between the original and the cloned program, while distinguishing the swappable maps between the two programs.

#### 3.1.1 Adaptmon

This is the only current programmable Plugin that can contain user-define eBPF data plane code. All its functionalities are explained in the [Adaptmon](api/plugins.md#Adaptmon) API doc. However, as previously described, if a custom control plane functionality is not provided, this Plugin allows users to retrieve their desired metrics using standard and general interactions, able to read the content of every eBPF maps and export it in a human-readable syntax.

In order to retrieve a specific metric, users need to issue a metric request to the desired HTTP endpoint (e.g., localhost:8080/plugins/adaptmon/ingress/metrics/METRIC_NAME) or to the **metrics** one if all metrics need to be retrieved. In the serverless mode, metrics can be retrieved by issuing to the Controller the method **execute\_cp\_function\_probe** passing **retrieve\_metrics** as the name of the method to be invoked.

### 3.2 Non-Programmable

This collection of Plugins contains all those which cannot accept dynamic eBPF code, but instead they use pre-defined templated within the [src](../dechainy/sourcebpf) directory, named with the Plugin name. As a result, a configuration of such plugins may only contain the **interface** to which attach the program, and the control plane routine additionally.

These plugins are not personalizable, but they are defined with a specific purpose, like a Firewall or a DDoS attack Mitigator.

#### 3.2.1 Firewall

This is an entire Firewall implemented in eBPF, like the one presented by Facebook [here](https://cilium.io/blog/2018/11/20/fb-bpf-firewall). It accepts rules to be injected/removed, which have to be compliant with this format:

`FirewallRule(obj: dict = None)`
:   Class to represent a firewall iptable-like rule
    
    Attributes:
        src (str): The source address to match. Default None.
        dst (str): The destination address to match. Default None.
        sport (int): The source port to match. Default None.
        dport (int): The destination port to match. Default None.
        l4proto (str): The Layer 4 protocol to match. Default None.
        tcpflags (str): A string containing the names of the TCP Flags to match. Default None.


At least one field needs to be provided in ordert o accept the rule. If successfully accepted, the rule is assigned a unique identifier, which can be used whether to substitute or remove it from the list of rules. Source and Destination IPs can be provided either with a netmask (e.g, 10.0.0.1/24) or single IP addresses. The default action when injecting a rule is to forbid the traffic, otherwise it automatically passes through the interface.

#### 3.2.2 Mitigator

This is a simpler version of the Firewall, which accepts easier rules based only on IP addresses and netmasks, ignoring additional information like protocols or ports. The simple rule is as follows:

`MitigatorRule(obj: dict = None)`
:   Class to represent a mitigator rule
    
    Attributes:
        ip (str): The Ip to block
        netmask (str): The length of the netmask. Default 32.

Following the same principle of the Firewall, upon the creation of a rule, a unique identifier is created, to interact with the rule.

## 4. Clusters

Clusters are groups of Plugin instances (probes) that needs to interact with each other. This is extremely useful when willing to create more complex programs within this framework, which are handled by a specific user-define logic, the control plane code. As a result, if the custom control plane code cannot be accepted in the system (i.e. it has been started with the **custom_cp: false** flag), clusters will not be available, since they would not make sense.

A typical cluster configuration is as follows:

`ClusterConfig(obj: dict = None)`
:   Class to represent a Cluster configuration
    
    Attributes:
        probes (List[ProbeConfig]): List of probes componing the cluster. Default [].
        time_window (int): periodic time to run the control plane function, if any. Default 10.
        cp_function (str): The cluster Controlplane function. Default None.
        name (str): The name of the cluster. Default None.


As previously anticipated, the **cp_function** needs to be provided, otherwise the configuration is rejected. In addition, in **probes** are listed all the probes that needs to be created within the cluster. As a result, in the control plane function users can directly access such probes, without passing through standard Controller calls.

An example of a cluster control plane code can be found [here](examples/src/cluster_cp.py), and [here](examples/cluster.json) the apposite system configuration.

When working in the server mode, the only endpoint exposed by the clusters is the **exec** endpoints, which will call the user-defined routine accordingly.

## 5. Control Plane Functions

Either probes or cluster control plane functions are characterized by four main internal function that can be called:

- **pre_compilation**: list of operations to be executed before compiling the probes (e.g., modifying the program cflags to be used, or prepare additional files or data structures)
- **post_compilation**: list of operations to be executed after compiling the probe (e.g., initializing eBPF maps with certain values)
- **reaction_function**: the main routine to be periodically executed according to the specified **time_window** in the configuration, if any (e.g., check that the incoming packets is less than a given value)
- **reaction_function_rest**: the control plane function to be executed when calling the **exec** endpoint via REST API.

In addition, users can define other internal auxiliary functions within this code that will be executed. Although, this functionality is not safe, meaning that the injected code is not executed within a safe and controlled environment (sandbox with lower privileges). Thus, when activating this feature, be aware of the possible risks that the system can issue.

## Hands on

To get started with the framework, users can either look at:

- configuration examples [here](examples) (json files)
- source code examples [here](examples/src) (both ebpf and python control planes)
- proposed and working tools [here](../tools)

Follow the proposed [tutorials](tutorial.md) to get familiar with the framework!
