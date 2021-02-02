Module dechainy.ebpf
====================

Functions
---------

    
`get_bpf_values(mode: int, program_type: str) ‑> Tuple[int, str, str]`
:   Function to return BPF map values according to ingress/egress and TC/XDP
    
    Args:
        mode (int): The program mode (XDP or TC)
        program_type (str): The program hook (ingress/egress)
    
    Returns:
        Tuple[int, str, str]: The values representing the mode, the suffix for maps names and parent interface

    
`get_cflags(mode: int, program_type: str, probe_id: int = 0, log_level: int = DPLogLevel.LOG_INFO) ‑> List[str]`
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

    
`get_swap_pivot() ‑> str`
:   Function to return the swap pivoting code
    
    Returns:
        str: The swap pivoting code

    
`is_batch_supp() ‑> bool`
:   Function to check whether the batch operations are supported for this system (kernel >= v5.6)
    
    Returns:
        bool: True if they are supported, else otherwise

    
`swap_compile(original_code: str) ‑> Tuple[str, str, str]`
:   Function to compile, if required, the original code in order to perform
    swap of eBPF maps.
    
    Args:
        original_code (str): The original code to be controlled
    
    Returns:
        Tuple[str]: Only the original code if no swaps maps, else the tuple containing
            also swap code and list of swappable maps

Classes
-------

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

`Program(interface: str, idx: int, mode: int, bpf: bcc.BPF, fd: int = None, probe_id: int = 0)`
:   Program class to handle both useful information and BPF program.
    
    Args:
        interface (str): The interface to attach the program to
        idx (int): The interface's index, retrieved using IPDB
        mode (int): The program mode (XDP or TC)
        bpf (BPF): The eBPF compiled program
        fd (int, optional): The file descriptor of the main function in the program. Defaults to None.
        probe_id (int, optional): The ID of the probe. Defaults to 0.
    
    Attributes:
        interface (str): The interface to attach the program to
        idx (int): The interface's index, retrieved using IPDB
        mode (int): The program mode (XDP or TC)
        bpf (BPF): The eBPF compiled program
        fd (int): The file descriptor of the main function in the program. Defaults to None.
        probe_id (int): The ID of the probe. Defaults to 0.
        is_destroyed (bool): Boolean value set to True when the instance is destroyed

`SwapStateCompile(programs: List[dechainy.ebpf.Program], pivot: dechainy.ebpf.Program, maps: List[str])`
:   Class storing the state of a program when the SWAP of at least 1 map is required.
    
    Args:
        programs (List[Program]): The list of the two compiled programs
        pivot (Program): The pivoting eBPF program compiled
        maps (List[str]): The list of maps defined as swappable
    
    Attributes:
        maps (List[str]): The maps defined as swappable
        index (int): The index of the current active program
        programs (List[Program]): The list containing the two programs compiled
        pivot (Program): The pivoting eBPF program compiled

    ### Methods

    `trigger_read(self)`
    :   Method to trigger the read of the maps, meaning to swap in and out the programs