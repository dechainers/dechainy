# Copyright 2020 DeChainy
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from atexit import register
from logging import getLogger, INFO, StreamHandler, Formatter
from threading import Thread
from types import ModuleType
from typing import Dict, List
from pyroute2 import IPRoute
from pyroute2.netlink.exceptions import NetlinkError
from bcc import BPF
from os.path import isfile, dirname
import ctypes as ct

from .exceptions import UnknownInterfaceException, NoCodeProbeException
from .ebpf import get_cflags, get_bpf_values, get_formatted_code, \
    get_pivoting_code, get_startup_code, Program, Metadata, swap_compile, get_swap_pivot, \
    SwapStateCompile
from .configurations import ClusterConfig, PluginConfig, ProbeConfig, \
    InterfaceHolder, ProbeCompilation, ClusterCompilation
from .plugins import Cluster, Plugin
from .utility import Singleton
from . import exceptions
from . import plugins


class Controller(metaclass=Singleton):
    """
    Singleton Controller class responsible of:
    - keeping track of clusters, probes and programs
    - compiling/removing programs from the interfaces

    All its public methods can be used both within an HTTP server, or locally by calling controller.method()
    """

    def __init__(self, log_level: int = INFO, plugins_to_load: List[str] = None):
        """Controller class, used to manage all interactions and the state of the application.

        Args:
            log_level (int, optional): The log level of the entire application. Defaults to INFO.
            plugins_to_load (List[str], optional): The list of plugins to active. Defaults to None (ALL).

        Attributes:
            logger (Logger): The class logger
            declarations (Dict[str, PluginConfig]): A dictionary containing, for each Plugin, its class declaration
                and eBPF codes (if not customizable)
            programs (Dict[int, InterfaceHolder]): A dictionary containing, for each interface index, the object
                holding all eBPF programs, for each type (TC, XDP, ingress/egress)
            probes (Dict[str, Dict[str, Plugin]]): A dictionary containing, for each plugin, an inner dictionary
                holding the Plugin instance, given its name
            clusters (Dict[str, Cluster]): A dictionary of Clusters, individualized by their names
            is_destroyed (bool): Variable to keep track of the instance lifecycle
            ip (IPRoute): the IPRoute instance, used for the entire app lifecycle
            startup (BPF): the startup eBPF compiled program, used to open perf buffers
        """
        # Initializing logger
        self.__logger = getLogger(self.__class__.__name__)
        self.__logger.setLevel(log_level)
        ch = StreamHandler()
        ch.setLevel(log_level)
        ch.setFormatter(
            Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        self.__logger.addHandler(ch)

        # Initializing local variables
        # TODO: add lock to instances map, clusters and programs
        self.__declarations: Dict[str, PluginConfig] = {}
        self.__programs: Dict[int, InterfaceHolder] = {}
        self.__probes: Dict[str, Dict[str, Plugin]] = {}
        self.__clusters: Dict[str, Cluster] = {}
        self.__is_destroyed: bool = False

        # Initialize IpRoute and check whether there's another instance of the
        # framework running
        self.__ip: IPRoute = IPRoute()

        try:
            self.__ip.link("add", ifname="DeChainy", kind="dummy")
        except NetlinkError as e:
            self.__is_destroyed = True
            err, _ = e.args
            self.__logger.error(
                "Either another instance of DeChainy is running, or the previous one has not terminated correctly."
                "In the latter case, try 'sudo ip link del DeChainy', and 'sudo tc qdisc del dev <interface> clsact'"
                "for every interface you used before." if err == 17 else "Need sudo privileges to run.")
            exit(1)

        # Compiling startup program with buffers
        self.__startup: BPF = BPF(text=get_startup_code())
        self.__startup['control_plane'].open_perf_buffer(self.__parse_packet)
        self.__startup['log_buffer'].open_perf_buffer(self.__log_function)
        Thread(target=self.__start_poll, args=(), daemon=True).start()
        register(self.__del__)

        # Verifying received plugins_to_load, else load all plugins
        default_plugins = [x.__name__.lower()
                           for x in plugins.Plugin.__subclasses__()]
        if plugins_to_load:
            for plugin in plugins_to_load:
                if plugin not in default_plugins:
                    self.__log_and_raise(
                        f'Plugin {plugin} not found, unable to load',
                        exceptions.PluginNotFoundException)
        else:
            plugins_to_load = default_plugins

        base_dir = dirname(__file__)
        # For each plugin to load, retrieve:
        # - Class declaration
        # - Ingress and Egress code if the probe is not Programmable like Adaptmon
        for plugin_name in plugins_to_load:
            class_def = getattr(plugins, plugin_name.capitalize())
            self.__probes[plugin_name] = {}
            codes = {"ingress": None, "egress": None}
            path = f'{base_dir}/sourcebpf/{plugin_name}.c'
            if not class_def.is_programmable() and isfile(path):
                with open(path, 'r') as fp:
                    code = fp.read()
                for hook in class_def.accepted_hooks():
                    codes[hook] = code
                self.__logger.info(
                    f'Loaded BPF code from file for Plugin {plugin_name}')
            self.__declarations[plugin_name] = PluginConfig(
                class_def, codes["ingress"], codes["egress"])

    def __del__(self):
        if self.__is_destroyed:
            return
        self.__is_destroyed = True
        self.__logger.info('Deleting eBPF programs')
        # Remove only once all kind of eBPF programs attached to all interfaces in use.
        for idx in self.__programs.keys():
            if self.__programs[idx].ingress_xdp or self.__programs[idx].egress_xdp:
                BPF.remove_xdp(
                    self.__programs[idx].name, self.__programs[idx].flags)
            if self.__programs[idx].ingress_tc or self.__programs[idx].egress_tc:
                self.__ip.tc("del", "clsact", idx)
        self.__ip.link("del", ifname="DeChainy")

    def __log_and_raise(self, msg: str, exception: callable):
        """Method to log a message and raise the specified exception

        Args:
            msg (str): The message string to log
            exception (callable): The exception to throw

        Raises:
            exception: The exception specified to be thrown
        """
        self.__logger.error(msg)
        raise exception(msg)

    #####################################################################
    # ---------------- Function to manage plugins -----------------------
    #####################################################################

    def get_active_plugins(self) -> List[str]:
        """Function to return all active plugins in the actual configuration.

        Returns:
            List[str]: All the active plugins names
        """
        return self.__declarations.keys()

    #####################################################################
    # ----------- Function to manage single probes ----------------------
    #####################################################################

    def __check_probe_exists(self, plugin_name: str, probe_name: str, is_creating=False):
        """Function to check whether a probe instance exists, and throw an exception if needed
        (when not creating a probe)

        Args:
            plugin_name (str): The name of the plugin
            probe_name (str): The name of the probe
            is_creating (bool, optional): True when creating the probe, no exception thrown. Defaults to False.
        """
        if plugin_name not in self.__declarations:
            self.__log_and_raise(
                f'Plugin {plugin_name} not found',
                exceptions.PluginNotFoundException)
        if is_creating and probe_name in self.__probes[plugin_name]:
            self.__log_and_raise(
                f'Probe {probe_name} for Plugin {plugin_name} already exist',
                exceptions.ProbeAlreadyExistsException)
        if not is_creating and probe_name not in self.__probes[plugin_name]:
            self.__log_and_raise(
                f'Probe {probe_name} for Plugin {plugin_name} not found',
                exceptions.ProbeNotFoundException)

    def delete_probe(self, plugin_name: str, probe_name: str) -> str:
        """Function to delete a probe of a specific plugin.

        Args:
            plugin_name (str): The name of the plugin
            probe_name (str): The name of the probe

        Returns:
            str: The name of the probe deleted
        """
        self.__check_probe_exists(plugin_name, probe_name)
        if self.__probes[plugin_name][probe_name].is_in_cluster():
            self.__log_and_raise(
                f'Probe {probe_name} of Plugin {plugin_name} is in a cluster',
                exceptions.ProbeInClusterException)
        self.__remove_probe_programs(
            self.__probes[plugin_name][probe_name].programs)
        del self.__probes[plugin_name][probe_name]
        self.__logger.info(
            f'Successfully deleted probe {probe_name} for plugin {plugin_name}')
        return probe_name

    def create_probe(
            self,
            plugin_name: str,
            probe_name: str,
            conf: ProbeConfig) -> str:
        """Method to create a probe instance of a specific plugin

        Args:
            plugin_name (str): The name of the plugin
            probe_name (str): The name of the probe
            conf (ProbeConfig): The configuration used to create the probe

        Raises:
            NoCodeProbeException: There is no eBPF code, neither for Ingress and Egress hook

        Returns:
            str: The name of the probe created
        """
        self.__check_probe_exists(plugin_name, probe_name, is_creating=True)
        conf.plugin_name = plugin_name
        conf.name = probe_name
        module: ModuleType = None
        # If the probe is not programmable, get already loaded codes, else check whether the probe has
        # a Control Plane function specified and load it as module.
        if not self.__declarations[plugin_name].class_declaration.is_programmable():
            accepted_hooks = self.__declarations[plugin_name].class_declaration.accepted_hooks(
            )
            for hook in ["ingress", "egress"]:
                conf[hook] = None if hook not in accepted_hooks or conf[hook] is False \
                    else self.__declarations[plugin_name][hook]
        if not conf.ingress and not conf.egress:
            raise NoCodeProbeException("There is no Ingress/Egress code active for this probe,"
                                       " must leave at least 1 accepted hook active")
        if conf.cp_function:
            module = ModuleType(f'{plugin_name}_{probe_name}')
            exec(conf.cp_function, module.__dict__)
        comp = self.__compile(
            conf, self.__declarations[plugin_name].class_declaration.get_cflags())
        prb = self.__declarations[plugin_name].class_declaration(
            conf, module, comp)
        self.__probes[plugin_name][probe_name] = prb
        self.__logger.info(
            f'Successfully created probe {probe_name} for plugin {plugin_name}')
        return probe_name

    def get_probe(self, plugin_name: str, probe_name: str) -> ProbeConfig:
        """Function to return a given probe of a given plugin

        Args:
            plugin_name (str): The name of the plugin
            probe_name (str): The name of the probe

        Returns:
            ProbeConfig: The configuration of the retrieved probe
        """
        self.__check_probe_exists(plugin_name, probe_name)
        return self.__probes[plugin_name][probe_name].__repr__()

    def execute_cp_function_probe(
            self,
            plugin_name: str,
            probe_name: str,
            func_name: str,
            *argv: tuple) -> any:
        """Function to call a specific Control Plane function of a probe

        Args:
            plugin_name (str): The name of the plugin
            probe_name (str): The probe which executed the function
            func (str): The name of the function to be called
            argv (tuple): The list of arguments

        Returns:
            any: The return type specified in the called function
        """
        self.__check_probe_exists(plugin_name, probe_name)
        try:
            return getattr(self.__probes[plugin_name][probe_name], f'{func_name}')(*argv)
        except AttributeError:
            self.__log_and_raise(
                f'Probe {probe_name} of Plugin {plugin_name} does not support function {func_name}',
                exceptions.UnsupportedOperationException)

    ######################################################################
    # ----------- Function to manage clusters -------------------------
    #####################################################################

    def __check_cluster_exists(self, cluster_name: str, is_creating=False):
        """Method to check whether a cluster exists, and throw exception if not creating

        Args:
            cluster_name (str): The name of the cluster
            is_creating (bool, optional): True if function called when creating cluster. Defaults to False.
        """
        if not is_creating and cluster_name not in self.__clusters:
            self.__log_and_raise(
                f'Cluster {cluster_name} not found',
                exceptions.ClusterNotFoundException)

    def create_cluster(self, cluster_name: str, conf: ClusterConfig) -> str:
        """Function to create a cluster given its name and the configuration.

        Args:
            cluster_name (str): The name of the cluster
            conf (ClusterConfig): The configuration of the cluster

        Returns:
            str: The name of the cluster created
        """
        self.__check_cluster_exists(cluster_name, is_creating=True)
        conf.name = cluster_name
        cluster_comp = ClusterCompilation()
        for probe_config in conf.probes:
            if probe_config.plugin_name not in cluster_comp:
                cluster_comp[probe_config.plugin_name] = {}
            probe_config.is_in_cluster = True
            self.create_probe(
                probe_config.plugin_name, probe_config.name, probe_config)
            cluster_comp[probe_config.plugin_name][probe_config.name] = \
                self.__probes[probe_config.plugin_name][probe_config.name]
        module = None
        # Loading the Control Plane function of the Cluster if any
        if conf.cp_function:
            module = ModuleType(cluster_name)
            exec(conf.cp_function, module.__dict__)
        self.__clusters[cluster_name] = plugins.Cluster(
            conf, module, cluster_comp)
        self.__logger.info(f'Successfully created Cluster {cluster_name}')
        return cluster_name

    def delete_cluster(self, cluster_name: str) -> str:
        """Function to delete a cluster given its name.

        Args:
            cluster_name (str): The name of the cluster

        Returns:
            str: The name of the deleted cluster
        """
        self.__check_cluster_exists(cluster_name)
        cluster = self.__clusters.pop(cluster_name)
        cluster.__del__()
        for plugin_name, probe_map in cluster.programs.items():
            for probe_name in probe_map.keys():
                self.__probes[plugin_name][probe_name]._config.is_in_cluster = False
                self.delete_probe(plugin_name, probe_name)
        self.__logger.info(f'Successfully deleted Cluster {cluster_name}')
        return cluster_name

    def get_cluster(self, cluster_name: str) -> ClusterConfig:
        """Function to return a Cluster configuration given its name

        Args:
            cluster_name (str): The name of the cluster

        Returns:
            ClusterConfig: The configuration of the retrieved cluster
        """
        self.__check_cluster_exists(cluster_name)
        return self.__clusters[cluster_name].__repr__()

    def execute_cp_function_cluster(self, cluster_name: str, func_name: str, *argv: tuple) -> any:
        """Function to execute a Control Plane function of a cluster

        Args:
            cluster_name (str): The name of the cluster
            func_name (str): The name of the function to call
            argv (tuple): The list of arguments

        Returns:
            any: The return type specified in the user-defined function
        """
        self.__check_cluster_exists(cluster_name)
        try:
            return getattr(self.__clusters[cluster_name], f'{func_name}')(*argv)
        except AttributeError:
            self.__log_and_raise(
                f'Cluster {cluster_name} does not support function {func_name}',
                exceptions.UnsupportedOperationException)

    ######################################################################
    # ------------- Function to manage bpf code --------------------------
    ######################################################################

    def __start_poll(self):
        """Function to poll perf buffers to wait for messages, both log and Packets"""
        while True:
            self.__startup.perf_buffer_poll()

    def __log_function(
            self,
            cpu: int,
            data: ct.POINTER(
                ct.c_void_p),
            size: int):
        """Method to log message received from the Dataplane

        Args:
            cpu (int): The CPU which has registered the message
            data (ct.POINTER): The raw structure of the message
            size (int): The size of the entire message
        """

        class LogMessage(ct.Structure):
            """Inner LogMessage class, representing the entire data structure

            Attributes:
                metadata (Metadata): The metadata of the message
                level (c_uint64): The log level of the message
                args (c_uint64 array): Array of maximum 4 variables to format the string
                content (c_char array): The message string to log
            """
            _fields_ = [("metadata", Metadata),
                        ("level", ct.c_uint64),
                        ("args", ct.c_uint64 * 4),
                        ("content", ct.c_char * (size - (ct.sizeof(ct.c_uint16) * 4) - (ct.sizeof(ct.c_uint64) * 4)))]

        # TODO: check and implement LOG LEVEL controls
        message = ct.cast(data, ct.POINTER(LogMessage)).contents
        decoded = message.content.decode()
        args = tuple([message.args[i] for i in range(0, decoded.count('%'))])
        formatted = decoded % args
        self.__logger.info(
            f'DP log message from Probe({message.metadata.probe_id}) CPU({cpu}) '
            f'PType({message.metadata.ptype}) IfIndex({message.metadata.ifindex}): {formatted}')

    def __parse_packet(self, cpu: int, data: ct.POINTER(ct.c_void_p), size: int):
        """Method to parse a packet received from the Dataplane

        Args:
            cpu (int): The CPU which registered the packet
            data (ct.POINTER): The raw data representing the packet
            size (int): The size of the entire metadata and packet
        """

        class Packet(ct.Structure):
            """Class representing a packet forwarded to the control plane

            Attributes:
                metadata (Metadata): The metadata associated to the message
                raw (c_ubyte array): The raw data as byte array
            """
            _fields_ = [("metadata", Metadata),
                        ("raw", ct.c_ubyte * (size - ct.sizeof(Metadata)))]

        skb_event = ct.cast(data, ct.POINTER(Packet)).contents

        # TODO: forward to probe in order to handle packet
        # TODO: create a Packet class to simplify parse
        self.__logger.info(
            f'CP handle packet from Probe {skb_event.metadata.probe_id} CPU({cpu}) PType({skb_event.metadata.ptype})')

    def __remove_probe_programs(self, conf: ProbeCompilation):
        """Method to remove the programs associated to a specific probe

        Args:
            conf (ProbeCompilation): The object containing the programs
        """
        types = ["ingress", "egress"]
        self.__logger.info('Deleting Probe programs')
        # Iterating through Ingress-Egress
        for i, program_type in enumerate(types):
            if not conf[program_type]:
                continue
            program = conf[program_type]
            # Retrieving the eBPF values given the config parameters
            mode, mode_map_name, _ = get_bpf_values(program.mode, program_type)
            next_map_name = f'{program_type}_next_{mode_map_name}'
            type_of_interest = f'{program_type}_{mode_map_name}'

            target = self.__programs[program.idx][type_of_interest]
            # TODO: dumb IDs, not safe when deleting a probe in the middle
            current_probes = len(target)
            # Checking if only two programs left into the interface, meaning
            # that also the pivoting has to be removed
            if current_probes == 2:
                for x in target:
                    x.__del__()
                self.__programs[program.idx][type_of_interest] = []
                # Checking if also the class act or the entire XDP program can
                # be removed
                if not self.__programs[program.idx][f'{types[int(not i)]}_{mode_map_name}']:
                    if mode == BPF.SCHED_CLS:
                        self.__ip.tc("del", "clsact", program.idx)
                    else:
                        BPF.remove_xdp(program.interface,
                                       self.__programs[program.idx][0].flags)
                continue

            # Retrieving the index of the Program retrieved
            index = target.index(program)
            if index + 1 != current_probes:
                # The program is not the last one in the list, so
                # modify program CHAIN in order that the previous program calls the
                # following one instead of the one to be removed
                if not target[0][next_map_name][program.probe_id - 1].red_idx:
                    target[0][next_map_name][program.probe_id - 1] =  \
                        ct.c_int(target[index + 1].fd)
            else:
                # The program is the last one in the list, so set the previous
                # program to call the following one which will be empty
                target[0][next_map_name][program.probe_id - 1] = \
                    target[0][next_map_name][program.probe_id + 1]
            del self.__programs[program.idx][type_of_interest][0][next_map_name][program.probe_id]
            target[index].__del__()
            del self.__programs[program.idx][type_of_interest][index]

    def __inject_pivot(
            self,
            mode: int,
            flags: int,
            offload_device: str,
            interface: str,
            idx: int,
            program_type: str,
            mode_map_name: str,
            parent: str):
        """Function to inject the pivoting program into a specific interface

        Args:
            mode (int): The mode of the program (XDP or TC)
            flags (int): The flags to be used in the mode
            offload_device (str): The device to which offload the program if any
            interface (str): The desired interface
            idx (int): The index of the interface
            program_type (str): The type of the program (Ingress/Egress)
            mode_map_name (str): The name of the map to use, retrieved from bpf helper function
            parent (str): The parent interface

        """
        # Compiling the eBPF program
        b = BPF(
            text=get_pivoting_code(
                mode, program_type), cflags=get_cflags(
                mode, program_type), debug=False, device=offload_device)
        f = b.load_func('handler', mode, device=offload_device)

        if mode == BPF.XDP:
            b.attach_xdp(interface, f, flags=flags)
        else:
            # Checking if already created the class act for the interface
            if not self.__programs[idx][f'ingress_{mode_map_name}'] \
                    and not self.__programs[idx][f'egress_{mode_map_name}']:
                self.__ip.tc("add", "clsact", idx)
            self.__ip.tc("add-filter", "bpf", idx, ':1', fd=f.fd, name=f.name,
                         parent=parent, classid=1, direct_action=True)
        self.__programs[idx][f'{program_type}_{mode_map_name}'].append(
            Program(interface, idx, mode, b, b.load_func('handler', mode).fd))

    def __compile(self, config: ProbeConfig, plugin_cflags: List[str]) -> ProbeCompilation:
        """Internal Function to compile a probe and inject respective eBPF programs

        Args:
            config (ProbeConfig): The probe configuration
            plugin_class (List[str]): The plugin class declaration belonging to the probe

        Returns:
            ProbeCompilation: A ProbeCompilation object containing the programs and the CP function if any
        """
        ret = ProbeCompilation()
        self.__logger.info(
            f'Compiling eBPF program {config.name}({config.plugin_name})')

        # Checking if the interface exists
        try:
            idx = self.__ip.link_lookup(ifname=config.interface)[0]
        except IndexError:
            self.__log_and_raise(
                f'Interface {config.interface} not available',
                UnknownInterfaceException)

        # For ingress-egress
        for program_type in ["ingress", "egress"]:
            # If not specified hook for the program type skip
            if not config[program_type]:
                ret[program_type] = None
                continue

            # Retrieve eBPF values given Mode and program type
            mode, flags, offload_device, mode_map_name, parent = get_bpf_values(
                config.mode, config.flags, config.interface, program_type)
            map_of_interest = f'{program_type}_{mode_map_name}'

            # Checking if the interface has already been used so there's already
            # Holder structure
            if idx not in self.__programs:
                self.__programs[idx] = InterfaceHolder(
                    config.interface, flags, offload_device)
            elif program_type == "ingress":
                flags, offload_device = self.__programs[idx].flags, self.__programs[idx].offload_device

            # If the array representing the hook is empty, inject the pivot code
            if not self.__programs[idx][map_of_interest]:
                self.__inject_pivot(mode, flags, offload_device, config.interface,
                                    idx, program_type, mode_map_name, parent)

            self.__logger.info(
                f'Attaching program {config.name} to chain {program_type}, '
                f'interface {config.interface}, mode {mode_map_name}')
            current_probes = len(self.__programs[idx][map_of_interest])

            original_code, swap_code, maps = swap_compile(
                config[program_type])
            code_to_compile = original_code if not swap_code else get_swap_pivot()
            cflags = plugin_cflags + \
                get_cflags(mode, program_type,
                           current_probes, config.log_level)

            red_idx = None
            if config.redirect and program_type == "ingress":
                red_idx = self.__ip.link_lookup(ifname=config.redirect)[0]
                cflags.append("-DNEED_REDIRECT=1")
                if red_idx not in self.__programs:
                    self.__programs[red_idx] = InterfaceHolder(
                        config.redirect, flags, offload_device)
                    self.__inject_pivot(
                        mode, flags, offload_device, config.redirect, red_idx, program_type, mode_map_name, parent)
                # TODO: Next instruction when needed? It always calls bpf_redirect...
                self.__programs[idx][map_of_interest][0][f'{program_type}_next_{mode_map_name}'][current_probes] = \
                    ct.c_int(self.__programs[red_idx][map_of_interest][0].fd)

            # Compiling BPF given the formatted code, CFLAGS for the current Mode and CFLAGS
            # for the specific Plugin class if any
            b = BPF(
                text=get_formatted_code(
                    mode,
                    program_type,
                    code_to_compile),
                debug=config.debug,
                cflags=plugin_cflags + cflags,
                device=offload_device)

            # Loading compiled "internal_handler" function and set the previous
            # plugin program to call in the CHAIN to the current function
            # descriptor
            p = Program(config.interface, idx, mode, b,
                        b.load_func('internal_handler', mode, device=offload_device).fd, current_probes, red_idx)
            if current_probes - 1 not in self.__programs[idx][map_of_interest][0][f'{program_type}_next_{mode_map_name}']:
                self.__programs[idx][map_of_interest][0][
                    f'{program_type}_next_{mode_map_name}'][current_probes - 1] = ct.c_int(p.fd)
            ret[program_type] = p
            if swap_code:
                b1 = BPF(text=get_formatted_code(mode, program_type, original_code),
                         debug=config.debug,
                         cflags=cflags,
                         device=offload_device)
                b2 = BPF(text=get_formatted_code(mode, program_type, swap_code),
                         debug=config.debug,
                         cflags=cflags,
                         device=offload_device)
                p1 = Program(config.interface, idx, mode,
                             b1, b1.load_func('internal_handler', mode, device=offload_device).fd, current_probes, red_idx)
                p2 = Program(config.interface, idx, mode,
                             b2, b2.load_func('internal_handler', mode, device=offload_device).fd, current_probes, red_idx)
                ret[program_type] = SwapStateCompile([p1, p2], p, maps)
            self.__programs[idx][map_of_interest].append(p)
        return ret
