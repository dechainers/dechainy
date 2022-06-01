Module dechainy.plugins
=======================

Classes
-------

`HookSetting(required: bool = False, cflags: List[str] = <factory>, code: str = None, program_ref: Type[weakref] = <function HookSetting.<lambda>>)`
:   Class to represent the configuration of a hook (ingress/egress)
    
    Attributes:
        required (bool): True if the hook is required for compilation. Default to False
        cflags (List[str]): List of cflags to be used when compiling eBPF programs. Default to [].
        code (str): The source code program. Default to None.

    ### Class variables

    `cflags: List[str]`
    :

    `code: str`
    :

    `required: bool`
    :

    ### Methods

    `program_ref() ‑> Type[weakref]`
    :

`Probe(name: str, interface: str, plugin_id: int, probe_id: int, mode: int = 3, flags: int = 2, ingress: dechainy.plugins.HookSetting = <factory>, egress: dechainy.plugins.HookSetting = <factory>, debug: bool = False, log_level: Union[str, int] = 20)`
:   Class to represent a base probe and deliver common functionalities to
    further developed probes.
    
    Attributes:
        name (str): The name of the Probe.
        interface (str): The interface to which attach the programs.
        mode (int): The mode of inserting the programs. Default to BPF.SCHED_CLS.
        flags (int): The flags to be used if BPF.XDP mode. Default to XDPFlags.SKB_MODE.
        ingress (HookSetting): The configuration of the ingress hook. Default to HookSetting().
        ingress (HookSetting): The configuration of the egress hook. Default to HookSetting().
        debug (bool): True if the programs should be compiled in debug mode. Default to False.
        log_level (Union[str, int]): The level of logging to be used. Default to logging.INFO.
        flags (int): Flags used to inject eBPF program when in XDP mode, later inferred. Default to 0.
        _logger (logging.Logger): The probe logger.
    Raises:
        NoCodeProbeException: When the probe does not have either ingress nor egress code.

    ### Class variables

    `debug: bool`
    :

    `egress: dechainy.plugins.HookSetting`
    :

    `flags: int`
    :

    `ingress: dechainy.plugins.HookSetting`
    :

    `interface: str`
    :

    `log_level: Union[str, int]`
    :

    `mode: int`
    :

    `name: str`
    :

    `plugin_id: int`
    :

    `probe_id: int`
    :

    ### Instance variables

    `plugin_name: str`
    :   Property to return the name of the plugin.
        
        Returns:
            str: The name of the plugin.

    ### Methods

    `additional_cflags(self) ‑> List[str]`
    :   Method to include additional cflags programmed ad-hoc for the plugin.
        
        Returns:
            List[str]: List of the additional cflags.

    `handle_packet_cp(self, event: Type[_ctypes.Structure], cpu: int)`
    :   Method to handle a packet received from the apposite data plane code
        and forwarded from the Controller. Probes that wants to send packets
        to the userspace must override and implement this method
        
        Args:
            metadata (Metadata): The Metadata retrieved from the probe.
            log_level (int): Log Level to be used.
            message (ct.Array): The message as a ctype.
            args (ct.Array): The list of arguments used to format the message.
            cpu (int): The number of the CPU handling the message.

    `log_message(self, event: Type[_ctypes.Structure], cpu: int)`
    :   Method to log a message received from the apposite data plane code and
        forwarded from the Controller.
        
        Args:
            metadata (Metadata): The Metadata retrieved from the probe.
            log_level (int): Log Level to be used.
            message (ct.Array): The message as a ctype.
            args (ct.Array): The list of arguments used to format the message.
            cpu (int): The number of the CPU handling the message.

    `patch_hook(self, program_type: str, new_code: str = None, new_cflags: List[str] = [])`
    :   Method to patch the code of a specific hook of the probe.
        
        Args:
            program_type (str): The hook to be patched
            new_code (str): The new code to be used. Default None.
            new_cflags (List[str]): The new cflags to be used. Default [].

    `retrieve_metric(self, program_type: str, metric_name: str = None) ‑> <built-in function any>`
    :   Method to retrieve metrics from a hook, if any. If also the name is provided, then
        only the requested metric is returned.
        
        Args:
            program_type (str): The program type (Ingress/Egress).
            metric_name (str): The name of the metric.
        
        Raises:
            HookDisabledException: When there is no program attached to the hook.
            MetricUnspecifiedException: When the requested metric does not exist
        
        Returns:
            any: The value of the metric.