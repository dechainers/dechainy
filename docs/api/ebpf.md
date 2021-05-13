Module dechainy.ebpf
====================

Functions
---------

    
`get_bpf_values(mode: int, flags: int, interface: str, program_type: str) ‑> Tuple[int, int, str, str, str]`
:   Function to return BPF map values according to ingress/egress and TC/XDP
    
    Args:
        mode (int): The program mode (XDP or TC)
        flags (int): Flags to be used in the mode
        interface (str): The interface to which attach the program
        program_type (str): The program hook (ingress/egress)
    
    Returns:
        Tuple[int, int, str str, str]: The values representing the mode, the suffix for maps names and parent interface

    
`get_cflags(mode: int, program_type: str, probe_id: int = 0, log_level: int = 1) ‑> List[str]`
:   Function to return CFLAGS according to ingress/egress and TC/XDP
    
    Args:
        mode (int): The program mode (XDP or TC)
        program_type (str): The hook of the program (ingress/egress)
        probe_id (int, optional): The ID of the probe to be created. Defaults to 0.
        log_level (int, optional): The Log Level of the probe. Defaults to DPLogLevel.LOG_INFO.
    
    Returns:
        List[str]: The list of computed cflags

    
`get_formatted_code(mode: int, program_type: str, code: str) ‑> str`
:   Function to return the probe wrapper code according to ingress/egress, TC/XDP, and substitute dp_log function
    
    Args:
        mode (int): The program mode (XDP or TC)
        program_type (str): The program hook (ingress/egress)
        code (str, optional): The code to be formatted
    
    Returns:
        str: The code formatted accordingly

    
`get_pivoting_code(mode: int, program_type: str) ‑> str`
:   Function to return the pivoting code according to ingress/egress and TC/XDP
    
    Args:
        mode (int): The program mode (XDP or TC)
        program_type (str): The program hook (ingress/egress)
    
    Returns:
        str: The pivoting code for the hook

    
`get_startup_code() ‑> str`
:   Function to return the startup code for the entire framework
    
    Returns:
        str: The startup code

    
`is_batch_supp() ‑> bool`
:   Function to check whether the batch operations are supported for this system (kernel >= v5.6)
    
    Returns:
        bool: True if they are supported, else otherwise

    
`precompile_parse(original_code: str) ‑> Tuple[str, str, Dict[str, dechainy.configurations.MetricFeatures]]`
:   Function to compile additional functionalities from original code (swap, erase, and more)
    
    Args:
        original_code (str): The original code to be controlled
    
    Returns:
        Tuple[str, str, Dict[str, MetricFeatures]]: Only the original code if no swaps maps,
            else the tuple containing also swap code and list of metrics configuration

Classes
-------

`ClusterCompilation(*args, **kwargs)`
:   Class to represent a compilation of a Cluster object.
    
    Attributes:
        key (str): The name of the plugin
        value (List[Plugin]): List of probes for that specific plugin

    ### Ancestors (in MRO)

    * dechainy.utility.Dict
    * builtins.dict

`InterfaceHolder(name: str, flags: int, offload_device: str)`
:   Simple class to store information concerning the programs attached to an interface
    
    Attributes:
        name (str): The name of the interface
        flags (int): The flags used in injection
        offload_device (str): The name of the device to which offload the program if any
        ingress_xdp (List[Program]): The list of programs attached to ingress hook in XDP mode
        ingress_tc (List[Program]): The list of programs attached to ingress hook in TC mode
        egress_xdp (List[Program]): The list of programs attached to egress hook in XDP mode
        egress_tc (List[Program]): The list of programs attached to egress hook in TC mode

    ### Ancestors (in MRO)

    * dechainy.utility.Dict
    * builtins.dict

`LpmKey(*args, **kwargs)`
:   C struct representing the LPM_KEY
    
    Attributes:
        netmask_len (c_uint32): the length of the netmask
        ip (c_uint32): the ip specified

    ### Ancestors (in MRO)

    * _ctypes.Structure
    * _ctypes._CData

    ### Instance variables

    `ip`
    :   Structure/Union member

    `netmask_len`
    :   Structure/Union member

`Metadata(*args, **kwargs)`
:   C struct representing the pkt_metadata structure in Data Plane programs
    
    Attributes:
        ifindex (c_uint32): The interface on which the packet was received
        ptype (c_uint32): The program type ingress/egress
        probe_id (c_uint64): The ID of the probe

    ### Ancestors (in MRO)

    * _ctypes.Structure
    * _ctypes._CData

    ### Instance variables

    `ifindex`
    :   Structure/Union member

    `probe_id`
    :   Structure/Union member

    `ptype`
    :   Structure/Union member

`ProbeCompilation()`
:   Class representing the compilation object of a Probe
    
    Attributes:
        cp_function (ModuleType): The module containing the optional Controlplane functions
        ingress (Union[Program, SwapStateCompile]): Program compiled for the ingress hook
        egress (Union[Program, SwapStateCompile]): Program compiled for the egress hook

    ### Ancestors (in MRO)

    * dechainy.utility.Dict
    * builtins.dict

`Program(interface: str, idx: int, mode: int, bpf: bcc.BPF, fd: int = None, probe_id: int = 0, red_idx: int = 0, features: Dict[str, dechainy.configurations.MetricFeatures] = {})`
:   Program class to handle both useful information and BPF program.
    
    Args:
        interface (str): The interface to attach the program to
        idx (int): The interface's index, retrieved using IPDB
        mode (int): The program mode (XDP or TC)
        bpf (BPF): The eBPF compiled program
        fd (int, optional): The file descriptor of the main function in the program. Defaults to None.
        probe_id (int, optional): The ID of the probe. Defaults to 0.
        features (Dict[str, MetricFeatures]): The map of features if any. Default None.
    
    Attributes:
        interface (str): The interface to attach the program to
        idx (int): The interface's index, retrieved using IPDB
        mode (int): The program mode (XDP or TC)
        bpf (BPF): The eBPF compiled program
        fd (int): The file descriptor of the main function in the program. Defaults to None.
        probe_id (int): The ID of the probe. Defaults to 0.
        red_idx (int): Index of the interface packets are redirect, if needed
        is_destroyed (bool): Boolean value set to True when the instance is destroyed
        features (Dict[str, MetricFeatures]): The map of features if any. Default {}.

`SwapStateCompile(programs: List[dechainy.ebpf.Program], chain_map: bcc.table.TableBase)`
:   Class storing the state of a program when the SWAP of at least 1 map is required.
    
    Args:
        programs (List[Program]): The list of the two compiled programs
        pivot (Program): The pivoting eBPF program compiled
    
    Attributes:
        maps (List[str]): The maps defined as swappable
        index (int): The index of the current active program
        programs (List[Program]): The list containing the two programs compiled
        chain_map (TableBase): The eBPF table performing the chain
        programs_id (int): The probe ID of the programs
        features (Dict[str, MetricFeatures]): The map of features if any. Default None.

    ### Methods

    `trigger_read(self)`
    :   Method to trigger the read of the maps, meaning to swap in and out the programs