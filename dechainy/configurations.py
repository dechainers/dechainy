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
from typing import Callable, List, Union
from types import ModuleType
from logging import INFO
from bcc import BPF

from .ebpf import DPLogLevel, Program, SwapStateCompile
from .exceptions import MissingInterfaceInProbeException
from .utility import Dict


class AppConfig(Dict):
    """Class to represent the startup configuration in a startup.json file.

    Attributes:
        plugins (List[str]): List of plugins to enable. Default [] (ALL).
        cluster (List[ClusterConfig]): List of clusters to create at startup. Default [].
        probes (List[ProbeConfig]): List of probes to create at startup. Default [].
        server (ServerConfig): Server configuration, if any. Default None.
        log_level (int): Log level for the entire application. Default INFO.
    """

    def __init__(self, obj: dict = None):
        super().__init__()
        if obj is None:
            obj = {}
        self.plugins: List[str] = obj['plugins'] if 'plugins' in obj else []
        self.clusters: List[ClusterConfig] = [ClusterConfig(
            x) for x in obj['clusters']] if 'clusters' in obj else []
        self.probes: List[ProbeConfig] = [ProbeConfig(
            x) for x in obj['probes']] if 'probes' in obj else []
        self.server: ServerConfig = ServerConfig(
            obj['server']) if 'server' in obj else None
        self.log_level: int = obj['log_level'] if 'log_level' in obj else INFO


class ServerConfig(Dict):
    """Class to represent the Server configuration in a startup.json file.

    Attributes:
        address (str): Address to which start the server. Default 0.0.0.0.
        port (int): The port to which start the server. Default 8080.
    """

    def __init__(self, obj: dict = None):
        super().__init__()
        if obj is None:
            obj = {}
        self.address: str = obj['address'] if 'address' in obj else '0.0.0.0'
        self.port: int = obj['port'] if 'port' in obj else 8080


class ClusterConfig(Dict):
    """Class to represent a Cluster configuration

    Attributes:
        probes (List[ProbeConfig]): List of probes componing the cluster. Default [].
        time_window (int): periodic time to run the control plane function, if any. Default 10.
        cp_function (str): The cluster Controlplane function. Default None.
        name (str): The name of the cluster. Default None.
    """

    def __init__(self, obj: dict = None):
        super().__init__()
        if obj is None:
            obj = {}
        self.probes: List[ProbeConfig] = [ProbeConfig(
            x) for x in obj['probes']] if 'probes' in obj else []
        self.time_window: int = obj['time_window'] if 'time_window' in obj else 10
        self.cp_function: str = obj['cp_function'] if 'cp_function' in obj else None
        # Following values are overwritten by Controller)
        self.name: str = obj['name'] if 'name' in obj else None


class ProbeConfig(Dict):
    """Class to represent a Probe configuration.

    Attributes:
        interface (str): The interface to which attach the program
        mode (int): The mode to insert the program (XDP or TC). Default TC.
        time_window (int): Periodic time to locally call the Controlplane function, if any. Default 10.
        ingress (str): Code for the ingress hook. Default None.
        egress (str): Code for the egress hook. Default None.
        files (Dict[str, str]): Dictionary containing additional files for the probe. Default {}.
        debug (bool): True if the probe must be inserted in debug mode. Default False.
        plugin_name (str): The name of the plugin. Default None. (Set by Controller)
        name (str): The name of the probe. Default None. (Set by Controller)
        is_in_cluster (bool): True if the probe is inside a cluster. Default False. (Set by Controller)

    Raises:
        MissingInterfaceInProbeException: The interface specified does not exist in the device
    """

    def __init__(self, obj: dict = None):
        super().__init__()
        if obj is None:
            obj = {}
        if 'interface' not in obj:
            raise MissingInterfaceInProbeException(
                'ProbeConfig needs an interface specified')
        self.interface: str = obj['interface']
        self.mode: int = BPF.XDP if 'mode' in obj and obj['mode'] == "XDP" else BPF.SCHED_CLS
        self.time_window: int = obj['time_window'] if 'time_window' in obj else 10
        self.ingress: str = obj['ingress'] if 'ingress' in obj else None
        self.egress: str = obj['egress'] if 'egress' in obj else None
        self.cp_function: str = obj['cp_function'] if 'cp_function' in obj else None
        self.files: Dict[str, str] = obj['files'] if 'files' in obj else None
        self.debug: bool = obj['debug'] if 'debug' in obj else False
        self.log_level: int = DPLogLevel(
            obj['log_level']) if 'log_level' in obj else DPLogLevel.LOG_INFO
        # Following values are overwritten by Controller
        self.plugin_name: str = obj['plugin'] if 'plugin' in obj else None
        self.name: str = obj['name'] if 'name' in obj else None
        self.is_in_cluster: bool = False


class PluginConfig(Dict):
    """Class to represent a Plugin configuration

    Attributes:
        class_declaration (Callable): Class declaration of the plugin
        ingress (str): Code for the ingress hook, if not programmable.
        egress (str): Code for the egress hook, if not programmable.
    """

    def __init__(
            self,
            class_declaration: Callable,
            ingress_code: str,
            egress_code: str):
        super().__init__()
        self.class_declaration: Callable = class_declaration
        self.ingress: str = ingress_code
        self.egress: str = egress_code


class ProbeCompilation(Dict):
    """Class representing the compilation object of a Probe

    Attributes:
        cp_function (ModuleType): The module containing the optional Controlplane functions
        ingress (Union[Program, SwapStateCompile]): Program compiled for the ingress hook
        egress (Union[Program, SwapStateCompile]): Program compiled for the egress hook
    """

    def __init__(self):
        super().__init__()
        self.cp_function: ModuleType = None
        self.ingress: Union[Program, SwapStateCompile] = None
        self.egress: Union[Program, SwapStateCompile] = None


class ClusterCompilation(Dict):
    """Class to represent a compilation of a Cluster object.

    Attributes:
        key (str): The name of the plugin
        value (List[Plugin]): List of probes for that specific plugin
    """
    pass


class InterfaceHolder(Dict):
    """Simple class to store information concerning the programs attached to an interface

    Attributes:
        name (str): The name of the interface
        ingress_xdp (List[Program]): The list of programs attached to ingress hook in XDP mode
        ingress_tc (List[Program]): The list of programs attached to ingress hook in TC mode
        egress_xdp (List[Program]): The list of programs attached to egress hook in XDP mode
        egress_tc (List[Program]): The list of programs attached to egress hook in TC mode
    """

    def __init__(self, name: str):
        super().__init__()
        self.name: str = name
        self.ingress_xdp: List[Program] = []
        self.ingress_tc: List[Program] = []
        self.egress_tc: List[Program] = []
        self.egress_xdp: List[Program] = []


class FirewallRule(Dict):
    """Class to represent a firewall iptable-like rule

    Attributes:
        src (str): The source address to match. Default None.
        dst (str): The destination address to match. Default None.
        sport (int): The source port to match. Default None.
        dport (int): The destination port to match. Default None.
        l4proto (str): The Layer 4 protocol to match. Default None.
        tcpflags (str): A string containing the names of the TCP Flags to match. Default None.
    """

    def __init__(self, obj: dict = None):
        super().__init__()
        if obj is None:
            obj = {}
        self.src: str = obj["src"] if "src" in obj else None
        self.dst: str = obj["dst"] if "dst" in obj else None
        self.sport: int = int(obj["sport"]) if "sport" in obj else None
        self.dport: int = int(obj["dport"]) if "dport" in obj else None
        self.l4proto: str = obj["l4proto"] if "l4proto" in obj else None
        self.tcpflags: str = obj["tcpflags"] if "tcpflags" in obj else None
        if not self.src and not self.dst and not self.sport and not self.dport and not self.l4proto and not self.tcpflags:
            raise KeyError(
                "Impossible inserting a rule without specifying at least a field")

    def __eq__(self, other):
        if not isinstance(other, FirewallRule):
            return NotImplemented

        return self.src == other.src and self.dst == other.dst and \
            self.sport == other.sport and self.dport == other.dport and \
            self.l4proto == other.l4proto and self.tcpflag == other.tcpflag


class MitigatorRule(Dict):
    """Class to represent a mitigator rule

    Attributes:
        ip (str): The Ip to block
        netmask (str): The length of the netmask. Default 32.
    """

    def __init__(self, obj: dict = None):
        super().__init__()
        if obj is None:
            obj = {}
        if "ip" not in obj:
            raise KeyError(
                "Impossible inserting a rule without specifying the IP")
        self.netmask: str = obj["netmask"] if "netmask" in obj else 32
        self.ip: str = obj["ip"]

    def __eq__(self, other):
        if not isinstance(other, MitigatorRule):
            return NotImplemented
        return self.netmask_len == other.netmask_len and self.ip == other.ip
