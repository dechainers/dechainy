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
import atexit
from importlib import import_module
from inspect import isclass
from types import ModuleType
from typing import Dict, OrderedDict, List, Union
import sys
import logging
import os
import itertools
from dechainy.ebpf import EbpfCompiler
import ctypes as ct

from .plugins import Cluster, Probe
from .utility import Singleton, get_logger, log_and_raise
from .ebpf import Metadata
from . import exceptions


class Controller(metaclass=Singleton):
    """
    Singleton Controller class responsible of:
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
    """

    def __init__(self, log_level=logging.INFO, plugins_to_load=[]):
        self.__logger = get_logger(self.__class__.__name__, log_level=log_level)

        # TODO: add lock to instances map, clusters and programs
        self.__declarations: OrderedDict[str, ModuleType] = {}
        self.__probes: OrderedDict[str, Dict[str, Probe]] = {}
        self.__clusters: OrderedDict[str, Cluster] = {}
        self.__is_destroyed: bool = False
        self.__compiler: EbpfCompiler = EbpfCompiler(self.__packet_cp_callback, self.__log_cp_callback)

        target_dir = os.path.join(os.path.dirname(__file__), "plugins")
        if not plugins_to_load:
            plugins_to_load = [x for x in os.listdir(target_dir) if os.path.isdir(os.path.join(target_dir, x)) and not x.startswith("__") ]
        
        for plugin in plugins_to_load:
            path = os.path.join(target_dir, plugin, "ebpf.c")
            self.create_plugin(plugin, "{}.plugins.{}".format(__package__, plugin))
        
        atexit.register(self.__del__)
        
    def __del__(self):
        if self.__is_destroyed:
            return
        self.__is_destroyed = True
        self.__compiler.__del__()
        # Delete all Plugins and Clusters
        for v in self.__probes.values():
            for vv in v.values():
                vv.__del__()
        for v in self.__clusters.values():
            for vv in v.values():
                vv.__del__()

    def __packet_cp_callback(self, cpu: int, data: ct.POINTER(ct.c_void_p), size: int):
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
        plugin_name = next(itertools.islice(
            self.__probes.keys(), skb_event.metadata.plugin_id, None))
        probe_name = next(itertools.islice(
            self.__probes[plugin_name].keys(), skb_event.metadata.probe_id, None))
        self.__probes[plugin_name][probe_name].handle_packet_cp(
            skb_event.metadata, skb_event.raw, cpu)

    def __log_cp_callback(self, 
        cpu: int,
        data: ct.POINTER(ct.c_void_p),
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
                        ("message", ct.c_char * (size - (ct.sizeof(ct.c_uint16) * 4) - (ct.sizeof(ct.c_uint64) * 4)))]

        skb_event = ct.cast(data, ct.POINTER(LogMessage)).contents
        plugin_name = next(itertools.islice(
            self.__probes.keys(), skb_event.metadata.plugin_id, None))
        probe_name = next(itertools.islice(
            self.__probes[plugin_name].keys(), skb_event.metadata.probe_id, None))
        self.__probes[plugin_name][probe_name].log_message(
            skb_event.metadata, skb_event.level, skb_event.message, skb_event.args, cpu)

    #####################################################################
    # ---------------- Function to manage plugins -----------------------
    #####################################################################

    def __check_plugin_exists(self, plugin_name, is_creating=False):
        if is_creating and plugin_name in self.__declarations:
            log_and_raise(self.__logger,
                f'Plugin {plugin_name} already exists',
                exceptions.PluginAlreadyExistsException)
        if not is_creating and plugin_name not in self.__declarations:
            log_and_raise(self.__logger,
                f'Plugin {plugin_name} not found',
                exceptions.PluginNotFoundException)
    
    def get_plugin(self, plugin_name: str = None) -> Union[ModuleType, List[ModuleType]]:
        if not plugin_name: return self.__declarations
        self.__check_plugin_exists(plugin_name)
        return self.__declarations[plugin_name]
    
    def create_plugin(self, plugin_name, module_or_class):
        self.__check_plugin_exists(plugin_name, is_creating=True)
        if isinstance(module_or_class, str):
            try:
                module = import_module(module_or_class)
            except Exception as e:
                print(e)
                module = ModuleType(plugin_name)
                sys.modules[plugin_name] = module
                exec(module_or_class, module.__dict__)               
        elif isclass(module_or_class) or isinstance(module_or_class, ModuleType):
            module = module_or_class
        else:
            raise ValueError("No supported type {}".format(type(self.module_path)))
        self.__declarations[plugin_name] = module
        self.__probes[plugin_name] = {}
        
    def delete_plugin(self, plugin_name):
        # TODO: check all probes and clusters which need to be deleted
        self.__check_plugin_exists(plugin_name)
        del self.__declarations[plugin_name]
        
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
        self.__check_plugin_exists(plugin_name)
        if is_creating and probe_name in self.__probes[plugin_name]:
            log_and_raise(self.__logger,
                f'Probe {probe_name} for Plugin {plugin_name} already exist',
                exceptions.ProbeAlreadyExistsException)
        if not is_creating and probe_name not in self.__probes[plugin_name]:
            log_and_raise(self.__logger,
                f'Probe {probe_name} for Plugin {plugin_name} not found',
                exceptions.ProbeNotFoundException)

    def delete_probe(self, plugin_name: str, probe_name: str):
        """Function to delete a probe of a specific plugin.

        Args:
            plugin_name (str): The name of the plugin
            probe_name (str): The name of the probe

        Returns:
            str: The name of the probe deleted
        """
        probe = self.get_probe(plugin_name, probe_name)
        if probe.is_in_cluster:
            log_and_raise(self.__logger,
                f'Probe {probe_name} of Plugin {plugin_name} is in a cluster',
                exceptions.ProbeInClusterException)
        if probe._programs.ingress:
            self.__compiler.remove_hook("ingress", probe._programs.ingress)
        if probe._programs.egress:
            self.__compiler.remove_hook("egress", probe._programs.egress)
        del self.__probes[plugin_name][probe_name]
        self.__logger.info(
            f'Successfully deleted probe {probe_name} for plugin {plugin_name}')
    
    def create_probe(self, probe: Probe):
        """Method to create a probe instance of a specific plugin

        Args:
            plugin_name (str): The name of the plugin
            probe_name (str): The name of the probe
            conf (ProbeConfig): The configuration used to create the probe

        Raises:
            NoCodeProbeException: There is no eBPF code, neither for Ingress and Egress hook

        Returns:
            Plugin: The created probe
        """
        self.__check_probe_exists(probe.plugin_name, probe.name, is_creating=True)
        plugin_id = list(self.__probes.keys()).index(probe.plugin_name)
        probe_id = len(self.__probes[probe.plugin_name])
        for program_type in ["ingress", "egress"]:
            code = getattr(probe, program_type).code
            if not code: continue
            setattr(probe._programs, program_type, self.__compiler.compile_hook(program_type, code, probe.interface, probe.mode, probe.flags, getattr(probe, program_type).cflags, probe.debug, plugin_id, probe_id, probe.log_level))
        self.__probes[probe.plugin_name][probe.name] = probe
        self.__logger.info(f'Successfully created probe {probe.name} for plugin {probe.plugin_name}')
    
    def get_probe(self, plugin_name: str, probe_name: str = None) -> Probe:
        """Function to return a given probe of a given plugin

        Args:
            plugin_name (str): The name of the plugin
            probe_name (str): The name of the probe

        Returns:
            Plugin: The retrieved probe
        """
        if not probe_name:
            self.__check_plugin_exists(plugin_name)
            return self.__probes
        self.__check_probe_exists(plugin_name, probe_name)
        return self.__probes[plugin_name][probe_name]

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
            log_and_raise(self.__logger,
                f'Cluster {cluster_name} not found',
                exceptions.ClusterNotFoundException)

    def create_cluster(self, cluster_name: str, conf: ClusterConfig):
        """Function to create a cluster given its name and the configuration.

        Args:
            cluster_name (str): The name of the cluster
            conf (ClusterConfig): The configuration of the cluster

        Returns:
            str: The name of the cluster created
        """
        # TODO: Fix
        self.__check_cluster_exists(cluster_name, is_creating=True)
        if not conf.cp_function:
            log_and_raise(self.__logger,
                'No Control plane code speficied, the Cluster would not make sense',
                exceptions.ClusterWithoutCPException)
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
        module = ModuleType(cluster_name)
        sys.modules[cluster_name] = module
        exec(conf.cp_function, module.__dict__)
        if hasattr(module, "pre_compilation"):
            module.pre_compilation(conf)
        self.__clusters[cluster_name] = plugins.Cluster(
            conf, module, cluster_comp)
        self.__logger.info(f'Successfully created Cluster {cluster_name}')
    
    def delete_cluster(self, cluster_name: str):
        """Function to delete a cluster given its name.

        Args:
            cluster_name (str): The name of the cluster

        Returns:
            str: The name of the deleted cluster
        """
        cluster = self.get_cluster(cluster_name)
        for plugin_name, probe_map in cluster._programs.items():
            for probe_name in probe_map.keys():
                self.get_probe(plugin_name, probe_name).is_in_cluster = False
                self.delete_probe(plugin_name, probe_name)
        del self.__clusters[cluster_name]
        self.__logger.info(f'Successfully deleted Cluster {cluster_name}')

    def get_cluster(self, cluster_name: str = None) -> Cluster:
        """Function to return a Cluster configuration given its name

        Args:
            cluster_name (str): The name of the cluster

        Returns:
            ClusterConfig: The configuration of the retrieved cluster
        """
        if not cluster_name: return self.__clusters
        self.__check_cluster_exists(cluster_name)
        return self.__clusters[cluster_name]
