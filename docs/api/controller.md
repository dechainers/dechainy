Module dechainy.controller
==========================

Classes
-------

`Controller(log_level: int = 20, plugins_to_load: List[str] = None, custom_cp: bool = True)`
:   Singleton Controller class responsible of:
    - keeping track of clusters, probes and programs
    - compiling/removing programs from the interfaces
    
    All its public methods can be used both within an HTTP server, or locally by calling controller.method()
    
    Attributes:
        logger (Logger): The class logger
        declarations (Dict[str, PluginConfig]): A dictionary containing, for each Plugin,
                                            its class declaration and eBPF codes (if not customizable)
        programs (Dict[int, InterfaceHolder]): A dictionary containing, for each interface index,
                                            the object holding all eBPF programs, for each type (TC, XDP, ingress/egress)
        probes (Dict[str, Dict[str, Plugin]]): A dictionary containing, for each plugin,
                                            an inner dictionary holding the Plugin instance, given its name
        clusters (Dict[str, Cluster]): A dictionary of Clusters, individualized by their names
        custom_cp (bool): True if enabled the possibility to accept user-define Control plane code,
                                            False otherwise. Default True.
        is_destroyed (bool): Variable to keep track of the instance lifecycle
        ip (IPRoute): the IPRoute instance, used for the entire app lifecycle
        startup (BPF): the startup eBPF compiled program, used to open perf buffers

    ### Methods

    `create_cluster(self, cluster_name: str, conf: dechainy.configurations.ClusterConfig) ‑> str`
    :   Function to create a cluster given its name and the configuration.
        
        Args:
            cluster_name (str): The name of the cluster
            conf (ClusterConfig): The configuration of the cluster
        
        Returns:
            str: The name of the cluster created

    `create_probe(self, plugin_name: str, probe_name: str, conf: dechainy.configurations.ProbeConfig) ‑> str`
    :   Method to create a probe instance of a specific plugin
        
        Args:
            plugin_name (str): The name of the plugin
            probe_name (str): The name of the probe
            conf (ProbeConfig): The configuration used to create the probe
        
        Raises:
            NoCodeProbeException: There is no eBPF code, neither for Ingress and Egress hook
        
        Returns:
            str: The name of the probe created

    `delete_cluster(self, cluster_name: str) ‑> str`
    :   Function to delete a cluster given its name.
        
        Args:
            cluster_name (str): The name of the cluster
        
        Returns:
            str: The name of the deleted cluster

    `delete_probe(self, plugin_name: str, probe_name: str) ‑> str`
    :   Function to delete a probe of a specific plugin.
        
        Args:
            plugin_name (str): The name of the plugin
            probe_name (str): The name of the probe
        
        Returns:
            str: The name of the probe deleted

    `execute_cp_function_cluster(self, cluster_name: str, func_name: str) ‑> <built-in function any>`
    :   Function to execute a Control Plane function of a cluster
        
        Args:
            cluster_name (str): The name of the cluster
            func_name (str): The name of the function to call
            argv (tuple): The list of arguments
        
        Returns:
            any: The return type specified in the user-defined function

    `execute_cp_function_probe(self, plugin_name: str, probe_name: str, func_name: str, *argv: tuple) ‑> <built-in function any>`
    :   Function to call a specific Control Plane function of a probe
        
        Args:
            plugin_name (str): The name of the plugin
            probe_name (str): The probe which executed the function
            func (str): The name of the function to be called
            argv (tuple): The list of arguments
        
        Returns:
            any: The return type specified in the called function

    `get_active_plugins(self) ‑> List[str]`
    :   Function to return all active plugins in the actual configuration.
        
        Returns:
            List[str]: All the active plugins names

    `get_cluster(self, cluster_name: str) ‑> dechainy.configurations.ClusterConfig`
    :   Function to return a Cluster configuration given its name
        
        Args:
            cluster_name (str): The name of the cluster
        
        Returns:
            ClusterConfig: The configuration of the retrieved cluster

    `get_probe(self, plugin_name: str, probe_name: str) ‑> dechainy.configurations.ProbeConfig`
    :   Function to return a given probe of a given plugin
        
        Args:
            plugin_name (str): The name of the plugin
            probe_name (str): The name of the probe
        
        Returns:
            ProbeConfig: The configuration of the retrieved probe