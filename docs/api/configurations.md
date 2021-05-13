Module dechainy.configurations
==============================

Classes
-------

`AppConfig(obj: dict = None)`
:   Class to represent the startup configuration in a startup.json file.
    
    Attributes:
        plugins (List[str]): List of plugins to enable. Default [] (ALL).
        cluster (List[ClusterConfig]): List of clusters to create at startup. Default [].
        probes (List[ProbeConfig]): List of probes to create at startup. Default [].
        server (ServerConfig): Server configuration, if any. Default None.
        custom_cp (bool): True if the system can accept custom Control plane code, False otherwise. Default True.
        log_level (int): Log level for the entire application. Default INFO.

    ### Ancestors (in MRO)

    * dechainy.utility.Dict
    * builtins.dict

`ClusterConfig(obj: dict = None)`
:   Class to represent a Cluster configuration
    
    Attributes:
        probes (List[ProbeConfig]): List of probes componing the cluster. Default [].
        time_window (float): periodic time to run the control plane function, if any. Default 10.
        cp_function (str): The cluster Controlplane function. Default None.
        name (str): The name of the cluster. Default None.

    ### Ancestors (in MRO)

    * dechainy.utility.Dict
    * builtins.dict

`DPLogLevel(value, names=None, *, module=None, qualname=None, type=None, start=1)`
:   Class to represent the log level of a datapath program.

    ### Ancestors (in MRO)

    * enum.Enum

    ### Class variables

    `LOG_DEBUG`
    :

    `LOG_ERR`
    :

    `LOG_INFO`
    :

    `LOG_OFF`
    :

    `LOG_WARN`
    :

`FirewallRule(obj: dict = None)`
:   Class to represent a firewall iptable-like rule
    
    Attributes:
        src (str): The source address to match. Default None.
        dst (str): The destination address to match. Default None.
        sport (int): The source port to match. Default None.
        dport (int): The destination port to match. Default None.
        l4proto (str): The Layer 4 protocol to match. Default None.
        tcpflags (str): A string containing the names of the TCP Flags to match. Default None.

    ### Ancestors (in MRO)

    * dechainy.utility.Dict
    * builtins.dict

`MetricFeatures(swap: bool = False, empty: bool = False, export: bool = False)`
:   Class to represent all the possible features for an Adaptmon metric
    
    Attributes:
        swap(bool): True if the metric requires swapping programs, False otherwise
        empty(bool): True if the metric needs to be emptied, False otherwise
        export(bool): True if the metric needs to be exported, False otherwise

`MitigatorRule(obj: dict = None)`
:   Class to represent a mitigator rule
    
    Attributes:
        ip (str): The Ip to block
        netmask (int): The length of the netmask. Default 32.

    ### Ancestors (in MRO)

    * dechainy.utility.Dict
    * builtins.dict

`PluginConfig(class_declaration: Callable, ingress_code: str, egress_code: str)`
:   Class to represent a Plugin configuration
    
    Attributes:
        class_declaration (Callable): Class declaration of the plugin
        ingress (str): Code for the ingress hook, if not programmable.
        egress (str): Code for the egress hook, if not programmable.

    ### Ancestors (in MRO)

    * dechainy.utility.Dict
    * builtins.dict

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
        is_in_cluster (bool): True if the probe is inside a cluster. Default False. (Set by Controller)
    
    Raises:
        MissingInterfaceInProbeException: The interface specified does not exist in the device

    ### Ancestors (in MRO)

    * dechainy.utility.Dict
    * builtins.dict

`ServerConfig(obj: dict = None)`
:   Class to represent the Server configuration in a startup.json file.
    
    Attributes:
        address (str): Address to which start the server. Default 0.0.0.0.
        port (int): The port to which start the server. Default 8080.

    ### Ancestors (in MRO)

    * dechainy.utility.Dict
    * builtins.dict