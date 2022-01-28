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
import sys
import ctypes as ct

from abc import abstractclassmethod
from ast import Dict
import logging
import os
from dataclasses import dataclass, field
from types import ModuleType
from typing import List, Union
from ctypes import Array
from bcc.table import QueueStack, TableBase, ArrayBase

from ..ebpf import MetricFeatures, Program, ProbeCompilation, Metadata, BPF, SwapStateCompile, EbpfCompiler
from ..utility import ctype_to_normal, get_logger
from ..exceptions import HookDisabledException, MetricUnspecifiedException, NoCodeProbeException

          
@dataclass
class HookSetting:
    required: bool = False
    cflags: List[str] = field(default_factory=lambda: [])
    code: str = None
    
    def __post_init__(self):
        self.code = None

    
@dataclass
class Probe:
    """Base Class representing all Plugin entities.

    Args:
        config (ProbeConfig): The probe configuration
        module (ModuleType): The module containing additional user-defined functions
        programs (ProbeCompilation): The compiled eBPF programs
    """
    name: str
    interface: str
    mode: Union[str, int]
    ingress: HookSetting = HookSetting()
    egress: HookSetting = HookSetting()
    extra: dict = field(default_factory=lambda: {})
    debug: bool = False
    log_level: Union[str, int] = logging.INFO
    
    def __post_init__(self, path=__file__):
        if self.mode == 'TC':
            self.mode: int = BPF.SCHED_CLS
            self.flags: int = 0
        elif self.mode in ['XDP', 'XDP_SBK']:
            self.mode: int = BPF.XDP
            self.flags: int = (1 << 1)
        elif self.mode == 'XDP_DRV':
            self.mode: int = BPF.XDP
            self.flags: int = (1 << 2)
        else:
            self.mode = BPF.XDP
            self.flags = (1 << 3)

        self.is_in_cluster: bool = False
        self._is_destroyed: bool = False
        self._programs: ProbeCompilation = None
        
        if isinstance(self.log_level, str): self.log_level = logging._nameToLevel[self.log_level]
        self._logger = get_logger(self.__class__.__name__, log_level=self.log_level)
            
        for ttype in ["ingress", "egress"]:
            hook = getattr(self, ttype)
            if not hook.required:
                continue
            tmp = os.path.join(os.path.dirname(path), "{}.c".format(ttype))
            if not os.path.isfile(tmp):
                tmp = os.path.join(os.path.dirname(path), "ebpf.c")
            if os.path.isfile(tmp):
                with open(tmp, "r") as fp:
                    hook.code = fp.read()
                continue            
        if not self.ingress.code and not self.egress.code:
            raise NoCodeProbeException("No Ingress/Egress Code specified for the probe {}".format(self.name))
    
    def __del__(self):
        if self._is_destroyed:
            return
        self._is_destroyed = True
        self._logger.manager.loggerDict.pop(self._logger.name)
        if self._programs:
            del self._programs

    def __getitem__(self, key: str) -> Union[str, Program]:
        """Method to access directly Programs in the class

        Args:
            key (str): The key to search into the Programs dictionary

        Returns:
            Union[str, Program]: the name of the probe for the plugin (key) if Cluster, else the compiled Program
        """
        return self._programs[key] if not self._is_destroyed else exit(1)
    
    @property
    def plugin_name(self) -> str:
        return self.__class__.__name__.lower()

    def post_compilation(self, comp: ProbeCompilation):
        self._programs = comp

    @abstractclassmethod
    def handle_packet_cp(self, metadata: Metadata, data: Array, cpu: int):
        """Function to invoke the apposite control plane function
        to handle a Packet forwarded from the Data Plane. The invoked function
        must accept three parameters: 1) [Plugin|Cluster], 2) Metadata, 3) pypacket.ethernet.Ethernet
        Args:
            metadata (Metadata): The Metadata retrieved from the Data Plane probe
            data (Array): The raw bytes of the packet
            cpu (int): Number of the CPU handling the packet
        """
        self._logger.info(f'Received Packet to handle from CPU {cpu}')
        pass

    def log_message(self, metadata: Metadata, log_level: int, message: Array, args: Array, cpu: int):
        """Function to log a message received from the apposite Data Plane probe
        Args:
            metadata (Metadata): The Metadata retrieved from the probe.
            log_level (int): Log Level to be used.
            message (ct.Array): The message as a ctype.
            args (ct.Array): The list of arguments used to format the message.
            cpu (int): The number of the CPU handling the message.
        """
        decoded_message = message.decode()
        args = tuple([args[i] for i in range(0, decoded_message.count('%'))])
        formatted = decoded_message % args
        self._logger.log(log_level, f'Message from CPU={cpu}: {formatted}')
    
    def __do_retrieve_metric(map_ref: Union[QueueStack, TableBase], features: List[MetricFeatures]) -> any:
        """Internal function to retrieve data from the eBPF map

        Args:
            map_ref (Union[QueueStack, TableBase]): The reference to the eBPF map
            features (List[MetricFeatures]): The features associated to the map

        Returns:
            any: The list of values if multiple ones, or just the first one if it is the only one
        """
        ret = []
        if isinstance(map_ref, QueueStack):
            ret = [ctype_to_normal(x) for x in map_ref.values()]
        elif isinstance(map_ref, ArrayBase):
            ret = [ctype_to_normal(v) for _, v in map_ref.items_lookup_batch(
            )] if EbpfCompiler.is_batch_supp() else [ctype_to_normal(v) for v in map_ref.values()]
            if features.empty:
                length = len(ret)
                keys = (map_ref.Key * length)()
                new_values = (map_ref.Leaf * length)()
                holder = map_ref.Leaf()
                for i in range(length):
                    keys[i] = ct.c_int(i)
                    new_values[i] = holder
                map_ref.items_update_batch(keys, new_values)
        else:
            exception = False
            if EbpfCompiler.is_batch_supp()():
                try:
                    for k, v in map_ref.items_lookup_and_delete_batch() if features.empty else map_ref.items_lookup_batch():
                        ret.append((ctype_to_normal(k), ctype_to_normal(v)))
                except Exception:
                    exception = True
            if not ret and exception:
                for k, v in map_ref.items():
                    ret.append((ctype_to_normal(k), ctype_to_normal(v)))
                    if features.empty:
                        del map_ref[k]
        return str(ret[0]) if len(ret) == 1 else ret

    def retrieve_metric(self, program_type: str, metric_name: str = None) -> any:
        """Function to retrieve the value of a specific metric.

        Args:
            program_type (str): The program type (Ingress/Egress)
            metric_name (str): The name of the metric.

        Returns:
            any: The value of the metric.
        """
        if not getattr(self, program_type):
            raise HookDisabledException(
                f"The hook {program_type} is not active for this probe")
        if isinstance(self.programs[program_type], SwapStateCompile):
            self.programs[program_type].trigger_read()

        if metric_name:
            features = self.programs[program_type].features[metric_name]
            if not features.export:
                raise MetricUnspecifiedException(
                    f"Metric {metric_name} unspecified")
            return self.__do_retrieve_metric(self.programs[program_type][metric_name], features)
        ret = {}
        for map_name, features in self.programs[program_type].features.items():
            if not features.export:
                continue
            ret[map_name] = self.__do_retrieve_metric(
                self.programs[program_type][map_name], features)
        return ret


@dataclass
class Cluster:
    """Cluster entity class, to represent a group of probes.

    Args:
        config (ClusterConfig): The cluster configuration
        module (ModuleType): The module containing additional user-defined functions
        programs (ClusterCompilation): The dictionary of probes in the cluster
    """
    name: str
    probes: List[Probe]
    time_window: float = None
    cp_function: str = None
    extra: dict = field(default_factory=lambda: {})
    log_level: Union[str, int] = logging.INFO
    
    def __post_init__(self) -> None:
        self._programs : Dict[str, Dict[str, ProbeCompilation]] = None
        self._is_destroyed: bool = False
        self._module: ModuleType = None
        
        if isinstance(self.log_level, int):
            self.log_level = logging._nameToLevel(self.log_level)
            
        if self.cp_function:
            self._module = ModuleType(f'cluster_{self.name}')
            sys.modules[f'cluster_{self.probe_name}'] = self._module
            exec(self.cp_function, self._module.__dict__)
            
    def __del__(self):
        if self._is_destroyed:
            return
        self._is_destroyed = True
        del self._programs
        del self._module
        del sys.modules[f'cluster_{self.probe_name}']    
