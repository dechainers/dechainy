Module dechainy.utility
=======================

Functions
---------

    
`ctype_to_normal(obj: <built-in function any>) ‑> <built-in function any>`
:   Function to convert a ctype object into a Python Serializable one
    
    Args:
        obj (any): The ctypes object to be converted
    
    Returns:
        any: The object converted

    
`ipv4_to_network_int(address: str) ‑> int`
:   Function to conver an IPv4 address string into network byte order integer
    
    Args:
        address (str): the addess to be converted
    
    Returns:
        int: the big endian representation of the address

    
`ipv4_to_string(address: int) ‑> str`
:   Function to convert an IP address from its big endian format to string
    
    Args:
        address (int): the address expressed in big endian
    
    Returns:
        str: the address as string

    
`port_to_host_int(port: int) ‑> int`
:   Function to convert a port from network byte order to little endian
    
    Args:
        port (int): the big endian port to be converted
    
    Returns:
        int: the little endian representation of the port

    
`port_to_network_int(port: int) ‑> int`
:   Function to conver a port (integer) into its big endian representation
    
    Args:
        port (int): the value of the port
    
    Returns:
        int: the big endian representation of the port

    
`protocol_to_int(name: str) ‑> int`
:   Function to return the integer value of a protocol given its name
    
    Args:
        name (str): the name of the protocol
    
    Returns:
        int: the integer value of the protocol

    
`protocol_to_string(value: int) ‑> str`
:   Function to return the name of the protocol given its integer value
    
    Args:
        value (int): the value of the protocol
    
    Raises:
        Exception: the protocol has not been added to the map
    
    Returns:
        str: the name of the protocol

    
`remove_c_comments(text: str) ‑> str`
:   Function to remove C-like comments, working also in trickiest cases
    Useful link: https://stackoverflow.com/questions/36454069/how-to-remove-c-style-comments-from-code
    
    Args:
        text (str): the original text with comments
    
    Returns:
        str: the string sanitized from comments

Classes
-------

`CPThread(target: Callable, args: tuple, time_window: float)`
:   Utility class to create a daemon thread (stopped when destroying its proprietary)
    to execute a function locally every time_window.
    
    Args:
        target (Callable): The function to execute
        args (tuple): The arguments provided
        timeout (int): The periodic restart value
    
    Attributes:
        func (Callable): The function to be executed
        args (tuple): The arguments provided to the function
        time_window (int): The timeout used for the thread to re-start
    
    This constructor should always be called with keyword arguments. Arguments are:
    
    *group* should be None; reserved for future extension when a ThreadGroup
    class is implemented.
    
    *target* is the callable object to be invoked by the run()
    method. Defaults to None, meaning nothing is called.
    
    *name* is the thread name. By default, a unique name is constructed of
    the form "Thread-N" where N is a small decimal number.
    
    *args* is the argument tuple for the target invocation. Defaults to ().
    
    *kwargs* is a dictionary of keyword arguments for the target
    invocation. Defaults to {}.
    
    If a subclass overrides the constructor, it must make sure to invoke
    the base class constructor (Thread.__init__()) before doing anything
    else to the thread.

    ### Ancestors (in MRO)

    * threading.Thread

    ### Methods

    `run(self)`
    :   Function to execute the provided function, if no stop signal registered within the time_window provided.

    `stop(self)`
    :   Function called by the proprietary to stop the Thread

`Dict(*args, **kwargs)`
:   Utility class to define a Class  attributes accessible also with square brackets

    ### Ancestors (in MRO)

    * builtins.dict

    ### Descendants

    * dechainy.configurations.AppConfig
    * dechainy.configurations.ClusterConfig
    * dechainy.configurations.FirewallRule
    * dechainy.configurations.MitigatorRule
    * dechainy.configurations.PluginConfig
    * dechainy.configurations.ProbeConfig
    * dechainy.configurations.ServerConfig
    * dechainy.ebpf.ClusterCompilation
    * dechainy.ebpf.InterfaceHolder
    * dechainy.ebpf.ProbeCompilation

`Singleton(*args, **kwargs)`
:   Metatype utility class to define a Singleton Pattern
    
    Attributes:
        _instance(object): The instance of the Singleton

    ### Ancestors (in MRO)

    * builtins.type