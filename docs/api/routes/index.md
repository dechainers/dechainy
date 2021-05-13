Module dechainy.routes
======================

Sub-modules
-----------
* dechainy.routes.adaptmon
* dechainy.routes.firewall
* dechainy.routes.mitigator

Functions
---------

    
`exec_cluster_custom_cp(cluster_name: str) ‑> <built-in function any>`
:   Rest endpoint to exec the previously specified function of a Cluster instance
    
    Args:
        cluster_name (str): The name of the Cluster
    
    Returns:
        any: The value specified in the user-defined function

    
`exec_probe_custom_cp(plugin_name: str, probe_name: str) ‑> <built-in function any>`
:   Rest endpoint to exec the function previosly specified on a specific Plugin instance
    
    Args:
        plugin_name (str): The name of the plugin
        probe_name (str): The name of the instance
    
    Returns:
        any: The return value specified in the user-defined function

    
`index() ‑> str`
:   Rest endpoint to test whether the server is correctly working
    
    Returns:
        str: The default message string

    
`manage_clusters(cluster_name: str) ‑> Union[dechainy.configurations.ClusterConfig, str]`
:   Rest endpoint to get, create or modify a Cluster instance
    
    Args:
        cluster_name (str): The name of the Cluster instance
    
    Returns:
        Union[ClusterConfig, str]: The Cluster if GET, else its name

    
`manage_probe(plugin_name: str, probe_name: str) ‑> Union[dechainy.configurations.ProbeConfig, str]`
:   Rest endpoint to get, create or modify an instance of a given Plugin
    
    Args:
        plugin_name (str): The name of the Plugin
        probe_name (str): The name of the instance
    
    Returns:
        Union[ProbeConfig, str]: The instance if GET, else its name