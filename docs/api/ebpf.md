Module dechainy.ebpf
====================

Classes
-------

`EbpfCompiler(log_level: int = 20, packet_cp_callback: Callable = None, log_cp_callback: Callable = None)`
:   Class (Singleton) to handle eBPF programs compilation, injection, and deletion.
    
    Static Attributes:
    __logger (logging.Logger): The instance logger.
    __is_batch_supp (bool): True if batch operations are supported. Default to None.
    __base_dir (str): Path to the sourcebpf folder, where there are source eBPF codes.
    __PARENT_INGRESS_TC (str): Address of the parent ingress hook in TC.
    __PARENT_EGRESS_TC (str): Address of the parent egress hook in TC.
    __XDP_MAP_SUFFIX (str): Suffix used for eBPF maps in XDP mode.
    __TC_MAP_SUFFIX (str):Suffix used for eBPF maps in TC mode.
    __EPOCH_BASE (int): Base timestamp to compute UNIX timestamps in eBPF programs.
    __TC_CFLAGS (List[str]): List of cflags to be used in TC mode.
    __XDP_CFLAGS (List[str]): List of cflags to be used in XDP mode.
    __DEFAULT_CFLAGS (List[str]): List of default cflags.
    
    Attributes:
        __startup (BPF): Startup eBPF program, where logging and control plane buffers are declared.
        __interfaces_programs: Dictionary holding for each interface the list of programs
            and attributes to be used.

    ### Static methods

    `callback_wrapper(cpu, data, size, callback, log=True)`
    :

    `is_batch_supp() ‑> bool`
    :   Static method to check whether the batch operations are supported for this system (kernel >= v5.6).
        
        Returns:
            bool: True if they are supported, else otherwise.

    ### Methods

    `compile_hook(self, program_type: str, code: str, interface: str, mode: int, flags: int, cflags: List[str], debug: bool, plugin_id: int, probe_id: int, log_level: int) ‑> Union[dechainy.ebpf.Program, dechainy.ebpf.SwapStateCompile]`
    :   Method to compile program for a specific hook of an interface. If the compilation
        succeeded, then the program chain is updated with the new service.
        
        Args:
            program_type (str): The hook type (ingress/egress).
            code (str): The program source code.
            interface (str): The interface to which attach the compiled program.
            mode (int): The mode used for injecting the program.
            flags (int): The flags used by the mode when injecting the program.
            cflags (List[str]): The cflags for the program.
            debug (bool): True if the program has to be compiled with debug info.
            plugin_id (int): The id of the plugin.
            probe_id (int): The id of the probe.
            log_level (int): The loggin level.
        
        Raises:
            exceptions.UnknownInterfaceException: When the interface does not exist.
        
        Returns:
            Union[Program, SwapStateCompile]: The compiled program.

    `patch_hook(self, program_type: str, old_program: Union[dechainy.ebpf.Program, dechainy.ebpf.SwapStateCompile], new_code: str, new_cflags: List[str], log_level: int = 20) ‑> Union[dechainy.ebpf.Program, dechainy.ebpf.SwapStateCompile]`
    :   Method to patch a specific provided program belonging to a certain hook.
        After compiling the new program, if no error are arisen, the old program will be
        completely deleted and substituting with the new one, preserving its position
        in the program chain.
        
        Args:
            program_type (str): The type of the hook (ingress/egress).
            old_program (Union[Program, SwapStateCompile]): The old program to be replaced.
            new_code (str): The new source code to be compiled.
            new_cflags (List[str]): The new cflags to be used.
            log_level (int, optional): The log level of the program. Defaults to logging.INFO.
        
        Raises:
            exceptions.UnknownInterfaceException: When the provided program belongs to an
                unknown interface.
            exceptions.ProgramInChainNotFoundException: When the provided program has not
                been found in the chain.
        
        Returns:
            Union[Program, SwapStateCompile]: The patched program.

    `remove_hook(self, program_type: str, program: Union[dechainy.ebpf.Program, dechainy.ebpf.SwapStateCompile])`
    :   Method to remove the program associated to a specific hook. The program chain
        is updated by removing the service from the chain itself.
        
        Args:
            program_type (str): The hook type (ingress/egress).
            program (Union[Program, SwapStateCompile]): The program to be deleted.

`HookTypeHolder(programs: List[Union[dechainy.ebpf.SwapStateCompile, dechainy.ebpf.Program]] = <factory>, ids: List[int] = <factory>)`
:   Class to hold current programs and free IDs available for a specific hook of an interface.
    
    Attributes:
        programs (List[Program]): List of eBPF program injected.
        ids (List[int]): List of available IDs to be used for new programs.
        lock (RLock): Lock for the hook.

    ### Class variables

    `ids: List[int]`
    :

    `programs: List[Union[dechainy.ebpf.SwapStateCompile, dechainy.ebpf.Program]]`
    :

`InterfaceHolder(name: str, flags: int, offload_device: str, ingress_xdp: dechainy.ebpf.HookTypeHolder = <factory>, ingress_tc: dechainy.ebpf.HookTypeHolder = <factory>, egress_xdp: dechainy.ebpf.HookTypeHolder = <factory>, egress_tc: dechainy.ebpf.HookTypeHolder = <factory>)`
:   Simple class to store information concerning the programs attached to an interface.
    
    Attributes:
        name (str): The name of the interface.
        flags (int): The flags used in injection.
        offload_device (str): The name of the device to which offload the program if any.
        ingress_xdp (List[Program]): The list of programs attached to ingress hook in XDP mode.
        ingress_tc (List[Program]): The list of programs attached to ingress hook in TC mode.
        egress_xdp (List[Program]): The list of programs attached to egress hook in XDP mode.
        egress_tc (List[Program]): The list of programs attached to egress hook in TC mode.

    ### Class variables

    `egress_tc: dechainy.ebpf.HookTypeHolder`
    :

    `egress_xdp: dechainy.ebpf.HookTypeHolder`
    :

    `flags: int`
    :

    `ingress_tc: dechainy.ebpf.HookTypeHolder`
    :

    `ingress_xdp: dechainy.ebpf.HookTypeHolder`
    :

    `name: str`
    :

    `offload_device: str`
    :

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

    `ingress`
    :   Structure/Union member

    `length`
    :   Structure/Union member

    `plugin_id`
    :   Structure/Union member

    `probe_id`
    :   Structure/Union member

    `program_id`
    :   Structure/Union member

    `xdp`
    :   Structure/Union member

`MetricFeatures(swap: bool = False, empty: bool = False, export: bool = False)`
:   Class to represent all the possible features for an Adaptmon metric
    
    Attributes:
        swap(bool): True if the metric requires swapping programs, False otherwise
        empty(bool): True if the metric needs to be emptied, False otherwise
        export(bool): True if the metric needs to be exported, False otherwise

    ### Class variables

    `empty: bool`
    :

    `export: bool`
    :

    `swap: bool`
    :

`Program(interface: str, idx: int, mode: int, flags: int, code: str, program_id: int, probe_id: int, plugin_id: int, debug: bool = False, cflags: List[str] = <factory>, features: Dict[str, dechainy.ebpf.MetricFeatures] = <factory>, offload_device: str = None)`
:   Program class to handle both useful information and BPF program.
    
    Attributes:
        interface (str): The interface to attach the program to
        idx (int): The interface's index, retrieved using IPDB
        mode (int): The program mode (XDP or TC)
        flags (int): The flags used for injecting the program.
        code (str): The source code.
        program_id (int): The ID of the program.
        debug (bool): True if the program is compiled with debug info. Default to False.
        cflags (List[str]): List of cflags for the program. Default to [].
        features (Dict[str, MetricFeatures]): The map of features if any. Default {}.
        offload_device (str): Device used for offloading the program. Default to None
        bpf (BPF): The eBPF compiled program
        f (BPF.Function): The function loaded from the program injected in the chain.

    ### Descendants

    * dechainy.ebpf.SwapStateCompile

    ### Class variables

    `bpf: bcc.BPF`
    :

    `cflags: List[str]`
    :

    `code: str`
    :

    `debug: bool`
    :

    `f: bcc.BPF.Function`
    :

    `features: Dict[str, dechainy.ebpf.MetricFeatures]`
    :

    `flags: int`
    :

    `idx: int`
    :

    `interface: str`
    :

    `mode: int`
    :

    `offload_device: str`
    :

    `plugin_id: int`
    :

    `probe_id: int`
    :

    `program_id: int`
    :

    ### Methods

    `trigger_read(self)`
    :

`SwapStateCompile(interface: str, idx: int, mode: int, flags: int, code: str, program_id: int, probe_id: int, plugin_id: int, debug: bool = False, cflags: List[str] = <factory>, features: Dict[str, dechainy.ebpf.MetricFeatures] = <factory>, offload_device: str = None, chain_map: str = None, code_1: str = None, index: int = 0)`
:   Class storing the state of a program when the SWAP of at least 1 map is required.
    
    Attributes:
        index (int): The index of the current active program
        _programs (List[Program]): The list containing the two programs compiled.
        chain_map (TableBase): The eBPF table performing the chain.
        program_id (int): The ID of the programs.
        mode (int): The mode used for injecting eBPF programs.
        features (Dict[str, MetricFeatures]): The map of features if any. Default None.

    ### Ancestors (in MRO)

    * dechainy.ebpf.Program

    ### Class variables

    `bpf_1: bcc.BPF`
    :

    `chain_map: str`
    :

    `code_1: str`
    :

    `f_1: bcc.BPF.Function`
    :

    `index: int`
    :

    ### Methods

    `trigger_read(self)`
    :   Method to trigger the read of the maps, meaning to swap in and out the programs