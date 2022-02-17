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
import ctypes as ct
import logging
import os
import weakref
from dataclasses import dataclass, field
from typing import List, Type, Union

from bcc import XDPFlags
from bcc.table import ArrayBase, QueueStack, TableBase

from ..ebpf import BPF, EbpfCompiler, MetricFeatures, Program, SwapStateCompile
from ..exceptions import (HookDisabledException, MetricUnspecifiedException,
                          NoCodeProbeException, ProbeNotFoundException)
from ..utility import ctype_to_normal, get_logger


@dataclass
class HookSetting:
    """Class to represent the configuration of a hook (ingress/egress)

    Attributes:
        required (bool): True if the hook is required for compilation. Default to False
        cflags (List[str]): List of cflags to be used when compiling eBPF programs. Default to [].
        code (str): The source code program. Default to None.
    """
    required: bool = False
    cflags: List[str] = field(default_factory=lambda: [])
    code: str = None
    program_ref: Type[weakref.ReferenceType] = lambda: None


@dataclass
class Probe:
    """Class to represent a base probe and deliver common functionalities to
    further developed probes.

    Attributes:
        name (str): The name of the Probe.
        interface (str): The interface to which attach the programs.
        mode (int): The mode of inserting the programs. Default to BPF.SCHED_CLS.
        flags (int): The flags to be used if BPF.XDP mode. Default to XDPFlags.SKB_MODE.
        ingress (HookSetting): The configuration of the ingress hook. Default to HookSetting().
        ingress (HookSetting): The configuration of the egress hook. Default to HookSetting().
        extra (dict): The dictionary containing extra information to be used. Default to {}.
        debug (bool): True if the programs should be compiled in debug mode. Default to False.
        log_level (Union[str, int]): The level of logging to be used. Default to logging.INFO.
        flags (int): Flags used to inject eBPF program when in XDP mode, later inferred. Default to 0.
        _logger (logging.Logger): The probe logger.
    Raises:
        NoCodeProbeException: When the probe does not have either ingress nor egress code.
    """
    name: str
    interface: str
    mode: int = BPF.SCHED_CLS
    flags: int = XDPFlags.SKB_MODE
    ingress: HookSetting = field(default_factory=lambda: HookSetting())
    egress: HookSetting = field(default_factory=lambda: HookSetting())
    extra: dict = field(default_factory=lambda: {})
    debug: bool = False
    log_level: Union[str, int] = logging.INFO

    def __post_init__(self, path=__file__):
        if isinstance(self.log_level, str):
            self.log_level = logging._nameToLevel[self.log_level]
        self._logger: logging.Logger = get_logger(
            self.__class__.__name__, log_level=self.log_level)

        for ttype in ["ingress", "egress"]:
            hook = getattr(self, ttype)
            hook.code = None
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
            raise NoCodeProbeException(
                "No Ingress/Egress Code specified for the probe {}".format(self.name))

    def __del__(self):
        """Method to clear all resources associated to the probe, including
        eBPF program and logger."""
        self._logger.manager.loggerDict.pop(self._logger.name)
        del self._logger
        print("DELEEEETINGGGGG")

    def __getitem__(self, key: str) -> Union[str, Program]:
        """Method to access directly Programs in the class

        Args:
            key (str): The key to search into the Programs dictionary

        Returns:
            Union[str, Program]: the compiled Program
        """
        return getattr(self, key).program_ref()

    @property
    def plugin_name(self) -> str:
        """Property to return the name of the plugin.

        Returns:
            str: The name of the plugin.
        """
        return self.__class__.__name__.lower()

    def post_compilation(self):
        """Method to be called after eBPF programs associated to the probes
        are compiled. Additional functionalities can be implemented in derived
        Probe classes.
        """
        pass

    def handle_packet_cp(self, event: Type[ct.Structure], cpu: int):
        """Method to handle a packet received from the apposite data plane code
        and forwarded from the Controller. Probes that wants to send packets
        to the userspace must override and implement this method

        Args:
            metadata (Metadata): The Metadata retrieved from the probe.
            log_level (int): Log Level to be used.
            message (ct.Array): The message as a ctype.
            args (ct.Array): The list of arguments used to format the message.
            cpu (int): The number of the CPU handling the message.
        """
        self._logger.info(f'Received Packet to handle from CPU {cpu}')

    def log_message(self, event: Type[ct.Structure], cpu: int):
        """Method to log a message received from the apposite data plane code and
        forwarded from the Controller.

        Args:
            metadata (Metadata): The Metadata retrieved from the probe.
            log_level (int): Log Level to be used.
            message (ct.Array): The message as a ctype.
            args (ct.Array): The list of arguments used to format the message.
            cpu (int): The number of the CPU handling the message.
        """
        decoded_message = event.message.decode()
        args = tuple([event.args[i]
                      for i in range(0, decoded_message.count('%'))])
        formatted = decoded_message % args
        self._logger.log(event.level, 'Message from CPU={}, Hook={}, Mode={}: {}'.format(
            cpu,
            "ingress" if event.metadata.ingress else "egress",
            "xdp" if event.metadata.xdp else "TC",
            formatted
        ))

    def __do_retrieve_metric(map_ref: Union[QueueStack, TableBase], features: List[MetricFeatures]) -> any:
        """Method internally used to retrieve data from the underlying eBPF map.

        Args:
            map_ref (Union[QueueStack, TableBase]): The reference to the eBPF map.
            features (List[MetricFeatures]): The features associated to the map.

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
        return ret

    def retrieve_metric(self, program_type: str, metric_name: str = None) -> any:
        """Method to retrieve metrics from a hook, if any. If also the name is provided, then
        only the requested metric is returned.

        Args:
            program_type (str): The program type (Ingress/Egress).
            metric_name (str): The name of the metric.

        Raises:
            HookDisabledException: When there is no program attached to the hook.
            MetricUnspecifiedException: When the requested metric does not exist

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