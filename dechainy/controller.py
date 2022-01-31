# Copyright 2022 DeChainers
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
import logging
import os
import itertools
import ctypes as ct
import shutil

from importlib import import_module
from types import ModuleType
from typing import Dict, OrderedDict, List, Union
from threading import RLock
from watchdog.events import FileSystemEventHandler, DirDeletedEvent, DirCreatedEvent
from watchdog.observers import Observer

from .plugins import Probe
from .utility import Singleton, get_logger
from .ebpf import Metadata, ProbeCompilation, EbpfCompiler
from . import exceptions, plugins_url


class SyncPluginsHandler(FileSystemEventHandler):

    def on_created(self, event):
        if not isinstance(event, DirCreatedEvent):
            return
        plugin_name = os.path.basename(event.src_path)
        if not plugin_name[0].isalpha():
            return
        with Controller._plugins_lock:
            try:
                Controller.check_plugin_validity(plugin_name)
                Controller._logger.info(
                    "Watchdog check for Plugin {} creation".format(plugin_name))
            except Exception:
                pass

    def on_deleted(self, event):
        if not isinstance(event, DirDeletedEvent):
            return
        plugin_name = os.path.basename(event.src_path)
        if not plugin_name[0].isalpha():
            return
        Controller().sync_plugin_probes(plugin_name)
        Controller._logger.info(
            "Watchdog check for Plugin {} removal".format(plugin_name))


class Controller(metaclass=Singleton):
    """
    Singleton Controller class responsible of:
    - keeping track of probes and programs
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
        is_destroyed (bool): Variable to keep track of the instance lifecycle
        ip (IPRoute): the IPRoute instance, used for the entire app lifecycle
        startup (BPF): the startup eBPF compiled program, used to open perf buffers
    """
    _plugins_lock: RLock = RLock()
    _logger = get_logger("Controller")

    def __init__(self, log_level=logging.INFO):
        Controller._logger.setLevel(log_level)
        self.__probes_lock: RLock = RLock()
        self.__probes: OrderedDict[str, Dict[str, Probe]] = {}
        self.__is_destroyed: bool = False
        self.observer = Observer()
        self.observer.schedule(SyncPluginsHandler(), os.path.join(
            os.path.dirname(__file__), "plugins"), recursive=True)
        self.observer.start()
        atexit.register(lambda: Controller().__del__()
                        if Controller() else None)
        self.__compiler: EbpfCompiler = EbpfCompiler(
            log_level=log_level, packet_cp_callback=lambda: Controller()._packet_cp_callback,
            log_cp_callback=lambda: Controller._log_cp_callback)

    def __del__(self):
        if self.__is_destroyed:
            return
        self.__is_destroyed = True
        if self.observer:
            self.observer.stop()
            self.observer.join()
        self.observer = None
        with self.__probes_lock:
            for k in list(self.__probes.keys()):
                for kk in list(self.__probes[k].keys()):
                    Controller._logger.info(
                        "Deleting Probe {} of Plugin {}".format(kk, k))
                    self.delete_probe(k, kk)
        self.__compiler.__del__()

    def _packet_cp_callback(self, cpu: int, data: ct.POINTER(ct.c_void_p), size: int):
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

    def _log_cp_callback(self,
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
    # ---------------- Function to manage plugins --------------------- #
    #####################################################################

    @staticmethod
    def __check_plugin_exists(plugin_name: str, is_creating: bool = False, update: bool = False):
        target = os.path.join(os.path.dirname(
            __file__), "plugins", plugin_name)
        if not is_creating and not os.path.isdir(target):
            raise exceptions.PluginNotFoundException(
                "Plugin {} not found".format(plugin_name))
        if is_creating and os.path.isdir(target):
            if not update:
                raise exceptions.PluginAlreadyExistsException(
                    "Plugin {} already exists".format(plugin_name))
            else:
                shutil.rmtree(target)

    @staticmethod
    def check_plugin_validity(plugin_name: str = None):
        with Controller._plugins_lock:
            plugin = Controller.get_plugin(plugin_name)
            cls = getattr(plugin, plugin_name.capitalize(), None)
            if not cls or not issubclass(cls, Probe):
                Controller.delete_plugin(plugin_name)
                raise exceptions.InvalidPluginException(
                    "Plugin {} is not valid".format(plugin_name))

    @staticmethod
    def get_plugin(plugin_name: str = None) -> Union[ModuleType, List[ModuleType]]:
        with Controller._plugins_lock:
            target_dir = os.path.join(os.path.dirname(__file__), "plugins")
            if not plugin_name:
                return [x for x in os.listdir(target_dir)
                        if os.path.isdir(os.path.join(target_dir, x)) and x[0].isalpha()]
            Controller.__check_plugin_exists(plugin_name)
            return import_module("{}.plugins.{}".format(__package__, plugin_name))

    @staticmethod
    def create_plugin(variable: str, update: bool = False):
        with Controller._plugins_lock:
            dest_path = os.path.join(os.path.dirname(__file__), "plugins")

            if os.path.isdir(variable):  # take from local path
                plugin_name = os.path.basename(variable)
                Controller.__check_plugin_exists(
                    plugin_name, is_creating=True, update=update)
                shutil.copytree(variable, os.path.join(dest_path, plugin_name))
            # download from remote custom
            elif any(variable.startswith(s) for s in ['http:', 'https:']):
                if not variable.endswith(".git"):
                    raise Exception(
                        "Not git repo, download the plugin and install it by your own please")
                plugin_name = variable.split("/")[-1][:-4]
                Controller.__check_plugin_exists(
                    plugin_name, is_creating=True, update=update)
                os.system("git clone {} {}".format(
                    variable, os.path.join(dest_path, plugin_name)))
            # download from remote default
            elif ''.join(ch for ch in variable if ch.isalnum()) == variable:
                plugin_name = variable
                Controller.__check_plugin_exists(
                    plugin_name, is_creating=True, update=update)
                os.system("""
                    git init {};
                    cd {};
                    git remote add origin {};
                    git config core.sparsecheckout true;
                    echo "{}/*" > .git/info/sparse-checkout;
                    git pull origin master;
                    rm -rf .git
                    """.format(dest_path, dest_path, plugins_url, plugin_name))
            else:
                raise exceptions.UnknownPluginFormatException(
                    "Unable to handle input {}".format(variable))
            Controller.check_plugin_validity(plugin_name)
        Controller._logger.info("Created Plugin {}".format(plugin_name))

    @staticmethod
    def delete_plugin(plugin_name: str = None):
        with Controller._plugins_lock:
            if plugin_name:
                Controller.__check_plugin_exists(plugin_name)
                shutil.rmtree(os.path.join(os.path.dirname(
                    __file__), "plugins", plugin_name))
            else:
                for plugin_name in Controller.get_plugin():
                    shutil.rmtree(os.path.join(os.path.dirname(
                        __file__), "plugins", plugin_name))
        Controller._logger.info("Deleted Plugin {}".format(plugin_name))

    #####################################################################
    # ------------------ Function to manage probes -------------------- #
    #####################################################################

    def delete_probe(self, plugin_name: str = None, probe_name: str = None):
        """Function to delete a probe of a specific plugin.

        Args:
            plugin_name (str): The name of the plugin
            probe_name (str): The name of the probe

        Returns:
            str: The name of the probe deleted
        """
        with self.__probes_lock:
            target = []
            if not plugin_name:
                target = [p for v in self.__probes.values()
                          for p in v.values()]
            else:
                if probe_name:
                    target = [self.get_probe(plugin_name, probe_name)]
                else:
                    target = [v for v in self.__probes[plugin_name].values()]
            if not target:
                raise exceptions.ProbeNotFoundException("No probes to delete")
            for probe in target:
                if probe._programs.ingress:
                    self.__compiler.remove_hook(
                        "ingress", probe._programs.ingress)
                if probe._programs.egress:
                    self.__compiler.remove_hook(
                        "egress", probe._programs.egress)
                del self.__probes[probe.plugin_name][probe.name]
                if not self.__probes[probe.plugin_name]:
                    del self.__probes[probe.plugin_name]
                probe.__del__()
                Controller._logger.info(
                    f'Successfully deleted Probe {probe.name} for Plugin {probe.plugin_name}')

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
        Controller.__check_plugin_exists(probe.plugin_name)
        with self.__probes_lock:
            if probe.plugin_name not in self.__probes:
                self.__probes[probe.plugin_name] = {}
            if probe.name in self.__probes[probe.plugin_name]:
                raise exceptions.ProbeAlreadyExistsException(
                    'Probe {} for Plugin {} already exist'.format(probe.name, probe.plugin_name))
            plugin_id = list(self.__probes.keys()).index(probe.plugin_name)
            probe_id = len(self.__probes[probe.plugin_name])
            comp = ProbeCompilation()
            for program_type in ["ingress", "egress"]:
                code = getattr(probe, program_type).code
                if not code:
                    continue
                setattr(comp, program_type, self.__compiler.compile_hook(program_type, code, probe.interface, probe.mode,
                                                                         probe.flags, getattr(
                                                                             probe, program_type).cflags,
                                                                         probe.debug, plugin_id, probe_id, probe.log_level))
            probe.post_compilation(comp)
            self.__probes[probe.plugin_name][probe.name] = probe
            Controller._logger.info(
                f'Successfully created Probe {probe.name} for Plugin {probe.plugin_name}')

    def get_probe(self, plugin_name: str = None, probe_name: str = None) -> Probe:
        """Function to return a given probe of a given plugin

        Args:
            plugin_name (str): The name of the plugin
            probe_name (str): The name of the probe

        Returns:
            Plugin: The retrieved probe
        """
        with self.__probes_lock:
            if not plugin_name:
                return self.__probes
            if plugin_name not in self.__probes or (probe_name and probe_name not in self.__probes[plugin_name]):
                Controller.__check_plugin_exists(plugin_name)
                if not probe_name:
                    return {}
                raise exceptions.ProbeNotFoundException(
                    'Probe {} for Plugin {} not found'.format(probe_name, plugin_name))
            return self.__probes[plugin_name] if not probe_name else self.__probes[plugin_name][probe_name]

    def sync_plugin_probes(self, plugin_name: str):
        with self.__probes_lock:
            if plugin_name not in self.__probes:
                return
            if not self.__probes[plugin_name]:
                del self.__probes[plugin_name]
                return
            try:
                Controller.__check_plugin_exists(plugin_name)
            except exceptions.PluginNotFoundException:
                Controller._logger.info(
                    "Found Probes of deleted Plugin {}".format(plugin_name))
                for k in list(self.__probes[plugin_name].keys()):
                    self.delete_probe(plugin_name, k)
