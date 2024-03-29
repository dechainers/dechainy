Module dechainy.utility
=======================

Functions
---------

    
`cint_type_limit(c_int_type)`
:   

    
`ctype_to_normal(obj: <built-in function any>) ‑> <built-in function any>`
:   Function to convert a ctype object into a Python Serializable one
    
    Args:
        obj (any): The ctypes object to be converted
    
    Returns:
        any: The object converted

    
`get_logger(name: str, filepath: str = None, log_level: int = 20) ‑> logging.Logger`
:   Function to create a logger or retrieve it if already created.
    
    Args:
        name (str): The name of the logger.
        filepath (str, optional): Path to the logging file, if required. Defaults to None.
        log_level (int, optional): Log Level taken from the logging module. Defaults to logging.INFO.
    
    Returns:
        logging.Logger: The logger created/retrieved.

    
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

    
`native_get_interface_ip_netmask(interface: str) ‑> Tuple[str, int]`
:   Function to return the IP address and netmask of
    a given interface.
    
    Args:
        interface (str): The interface of interest.
    
    Returns:
        Tuple[str, int]: The IP address and netmask.

    
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
    [New] Useful link: https://gist.github.com/ChunMinChang/88bfa5842396c1fbbc5b
    [Old] Useful link: https://stackoverflow.com/questions/36454069/how-to-remove-c-style-comments-from-code
    
    Args:
        text (str): the original text with comments
    
    Returns:
        str: the string sanitized from comments

Classes
-------

`Singleton(*args, **kwargs)`
:   Metatype utility class to define a Singleton Pattern
    
    Attributes:
        _instances(WeakValueDictionary): The instances of the Singletons

    ### Ancestors (in MRO)

    * builtins.type