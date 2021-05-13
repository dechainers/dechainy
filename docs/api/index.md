Module dechainy
===============

Sub-modules
-----------
* dechainy.configurations
* dechainy.controller
* dechainy.ebpf
* dechainy.exceptions
* dechainy.plugins
* dechainy.routes
* dechainy.utility

Functions
---------

    
`create_server(log_level=20, plugins_to_load: List[str] = None, custom_cp: bool = True) ‑> Tuple[flask.app.Flask, dechainy.controller.Controller]`
:   Function to return a Flask Server and a Controller given the parameters.
    It is allowed to have multiple servers, but they must share the same Controller
    instance, otherwise there could be problems with the network interfaces cards.
    
    Args:
        log_level ([type], optional): log level info integer. Defaults to INFO.
        plugins_to_load (List[str], optional): list of plugins to load. If None, then load all of them. Defaults to None.
        custom_cp (bool): True if the framework can accept dynamic Control Plane routines, False otherwise. Default True.
    
    Returns:
        Tuple[Flask, Controller]: [description]