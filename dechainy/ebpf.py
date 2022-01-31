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
from dataclasses import dataclass, field
import time
import logging
import threading
import os
import atexit
import ctypes as ct

from pyroute2 import IPRoute
from pyroute2.netlink.exceptions import NetlinkError
from re import finditer, MULTILINE
from subprocess import run, PIPE
from typing import Callable, Dict, List, Tuple, Union
from threading import RLock

from bcc import BPF
from bcc.table import QueueStack, TableBase

from .utility import Singleton, get_logger, remove_c_comments
from . import exceptions

########################################################################
#   #NOTE: generic/SKB (xdpgeneric), native/driver (xdp), and hardware offload (xdpoffload)
#   #define XDP_FLAGS_SKB_MODE      (1U << 1)
#   #define XDP_FLAGS_DRV_MODE      (1U << 2)
#   #define XDP_FLAGS_HW_MODE       (1U << 3)
########################################################################
BPF.TC_ACT_OK = 0
BPF.TC_ACT_SHOT = 2
BPF.TC_REDIRECT = 10
BPF.TC_STRUCT = '__sk_buff'
BPF.XDP_STRUCT = 'xdp_md'
BPF._MAX_PROGRAMS_PER_HOOK = 32


class Metadata(ct.Structure):
    """C struct representing the pkt_metadata structure in Data Plane programs

    Attributes:
        ifindex (c_uint32): The interface on which the packet was received
        length (c_uint32): The length of the packet
        ptype (c_uint8): The program type ingress/egress
        probe_id (c_uint8): The ID of the probe
        program_id (ct.c_uint16): The ID of the program
        plugin_id (ct.c_uint16): The ID of the plugin
        probe_id (ct.c_uint16): The ID of the probe within the plugin
    """
    _fields_ = [("ifindex", ct.c_uint32),
                ("length", ct.c_uint32),
                ("ingress", ct.c_uint8),
                ("xdp", ct.c_uint8),
                ("program_id", ct.c_uint16),
                ("plugin_id", ct.c_uint16),
                ("probe_id", ct.c_uint16)]


class LpmKey(ct.Structure):
    """C struct representing the LPM_KEY

    Attributes:
        netmask_len (c_uint32): the length of the netmask
        ip (c_uint32): the ip specified
    """
    _fields_ = [("netmask_len", ct.c_uint32),
                ("ip", ct.c_uint32)]


@dataclass
class MetricFeatures:
    """Class to represent all the possible features for an Adaptmon metric

    Attributes:
        swap(bool): True if the metric requires swapping programs, False otherwise
        empty(bool): True if the metric needs to be emptied, False otherwise
        export(bool): True if the metric needs to be exported, False otherwise
    """
    swap: bool = False
    empty: bool = False
    export: bool = False


@dataclass
class Program:
    """Program class to handle both useful information and BPF program.

    Attributes:
        interface (str): The interface to attach the program to
        idx (int): The interface's index, retrieved using IPDB
        mode (int): The program mode (XDP or TC)
        bpf (BPF): The eBPF compiled program
        fd (int): The file descriptor of the main function in the program. Defaults to None.
        program_id (int, optional): The ID of the program. Defaults to 0.
        is_destroyed (bool): Boolean value set to True when the instance is destroyed
        features (Dict[str, MetricFeatures]): The map of features if any. Default {}.
    """

    interface: str
    idx: int
    mode: int
    flags: int
    code: str
    program_id: int
    debug: bool = False
    cflags: List[str] = field(default_factory=lambda: [])
    features: Dict[str, MetricFeatures] = field(default_factory=lambda: {})
    offload_device: str = None

    def __post_init__(self):
        self.__is_destroyed = False
        self.bpf = BPF(text=self.code, debug=self.debug,
                       cflags=self.cflags, device=self.offload_device)
        self.f = self.bpf.load_func(
            'internal_handler', self.mode, device=self.offload_device)

    def __del__(self):
        if self.__is_destroyed:
            return
        # Calling the BCC defined cleanup function which would have been called while exitting
        self.__is_destroyed = True
        atexit.unregister(self.bpf.cleanup)
        self.bpf.cleanup()
        del self.bpf

    def __getitem__(self, key: str) -> Union[QueueStack, TableBase]:
        """Function to access directly the BPF map providing a key

        Args:
            key (str): The name of the map

        Returns:
            Union[QueueStack, TableBase]: The eBPF map requested
        """
        return self.bpf[key] if not self.__is_destroyed else exit(1)


@dataclass
class SwapStateCompile:
    """Class storing the state of a program when the SWAP of at least 1 map is required.

    Attributes:
        maps (List[str]): The maps defined as swappable
        index (int): The index of the current active program
        programs (List[Program]): The list containing the two programs compiled
        chain_map (TableBase): The eBPF table performing the chain
        programs_id (int): The probe ID of the programs
        features (Dict[str, MetricFeatures]): The map of features if any. Default None.
    """
    _programs: List[Program]
    _chain_map: TableBase

    def __post_init__(self):
        self.__is_destroyed = False
        self.__index: int = 0
        self.program_id: int = self._programs[0].program_id
        self.mode: int = self._programs[0].mode
        self.features: Dict[str, MetricFeatures] = self._programs[0].features

    def __del__(self):
        if self.__is_destroyed:
            return
        self.__is_destroyed = True
        if self._programs:
            for p in self._programs:
                p.__del__()
            self._programs.clear()

    def trigger_read(self):
        """Method to trigger the read of the maps, meaning to swap in and out the programs"""
        if self.__is_destroyed:
            exit(1)
        self.__index = (self.__index + 1) % 2
        self.__chain_map[self.program_id-1] = ct.c_int(
            self._programs[self.__index].f.fd)

    def __getitem__(self, key: any) -> any:
        """Method to read from a swapped-out program map the value, given the key

        Args:
            key (any): The key to be searched in the map

        Returns:
            any: The value corresponding to the provided key
        """
        if self.__is_destroyed:
            exit(1)
        index_to_read = int(not self.__index)
        if index_to_read == 1 and key in self.features:
            key += "_1"
        return self._programs[index_to_read][key]


@dataclass
class ProbeCompilation:
    """Class representing the compilation object of a Probe

    Attributes:
        ingress (Union[Program, SwapStateCompile]): Program compiled for the ingress hook
        egress (Union[Program, SwapStateCompile]): Program compiled for the egress hook
    """
    ingress: Union[Program, SwapStateCompile] = None
    egress: Union[Program, SwapStateCompile] = None


@dataclass
class HookTypeHolder:
    programs: List[Program] = field(default_factory=lambda: [])
    ids: List[int] = field(default_factory=lambda: list(
        range(1, BPF._MAX_PROGRAMS_PER_HOOK)))

    def __post_init__(self):
        self.lock: RLock = RLock()


@dataclass
class InterfaceHolder:
    """Simple class to store information concerning the programs attached to an interface

    Attributes:
        name (str): The name of the interface
        flags (int): The flags used in injection
        offload_device (str): The name of the device to which offload the program if any
        ingress_xdp (List[Program]): The list of programs attached to ingress hook in XDP mode
        ingress_tc (List[Program]): The list of programs attached to ingress hook in TC mode
        egress_xdp (List[Program]): The list of programs attached to egress hook in XDP mode
        egress_tc (List[Program]): The list of programs attached to egress hook in TC mode
    """
    name: str
    flags: int
    offload_device: str
    ingress_xdp: HookTypeHolder = HookTypeHolder()
    ingress_tc: HookTypeHolder = HookTypeHolder()
    egress_xdp: HookTypeHolder = HookTypeHolder()
    egress_tc: HookTypeHolder = HookTypeHolder()


class EbpfCompiler(metaclass=Singleton):
    __logger = get_logger("EbpfCompiler")
    __is_batch_supp = None
    __base_dir = os.path.join(os.path.dirname(__file__), "sourcebpf")
    __PARENT_INGRESS_TC = 'ffff:fff2'
    __PARENT_EGRESS_TC = 'ffff:fff3'
    __XDP_MAP_SUFFIX = 'xdp'
    __TC_MAP_SUFFIX = 'tc'

    # Computing EPOCH BASE time from uptime, to synchronize bpf_ktime_get_ns()
    with open(os.path.join(os.sep, "proc", "uptime"), 'r') as f:
        __EPOCH_BASE = int(
            (int(time.time() * 10**9) - int(float(f.readline().split()[0]) * (10 ** 9))))

    __TC_CFLAGS = [
        f'-DCTXTYPE={BPF.TC_STRUCT}',
        f'-DPASS={BPF.TC_ACT_OK}',
        f'-DDROP={BPF.TC_ACT_SHOT}',
        f'-DREDIRECT={BPF.TC_REDIRECT}',
        '-DXDP=0']

    __XDP_CFLAGS = [
        f'-DCTXTYPE={BPF.XDP_STRUCT}',
        f'-DBACK_TX={BPF.XDP_TX}',
        f'-DPASS={BPF.XDP_PASS}',
        f'-DDROP={BPF.XDP_DROP}',
        f'-DREDIRECT={BPF.XDP_REDIRECT}',
        '-DXDP=1']

    __DEFAULT_CFLAGS = [
        "-w",
        f'-DMAX_PROGRAMS_PER_HOOK={BPF._MAX_PROGRAMS_PER_HOOK}',
        f'-DEPOCH_BASE={__EPOCH_BASE}'] + [f'-D{x}={y}' for x, y in logging._nameToLevel.items()]

    def __init__(self, log_level: int = logging.INFO, packet_cp_callback: Callable = None, log_cp_callback: Callable = None):
        EbpfCompiler.__logger.setLevel(log_level)
        self.__interfaces_programs: Dict[int, InterfaceHolder] = {}
        self.__is_destroyed = False

        try:
            with IPRoute() as ip:
                ip.link("add", ifname="DeChainy", kind="dummy")
        except NetlinkError as e:
            self.__is_destroyed = True
            err, _ = e.args
            EbpfCompiler.__logger.error(
                "Either another instance of DeChainy is running, or the previous one has not terminated correctly."
                "In the latter case, try 'sudo ip link del DeChainy', and 'sudo tc qdisc del dev <interface> clsact'"
                "for every interface you used before." if err == 17 else "Need sudo privileges to run.")
            exit(err)

        # Compiling startup program with buffers
        # Variable to store startup code, containing the log buffer perf event map
        with open(os.path.join(EbpfCompiler.__base_dir, "startup.h"), 'r') as fp:
            startup_code = remove_c_comments(fp.read())

        self.__startup: BPF = BPF(text=startup_code)
        if packet_cp_callback:
            self.__startup['control_plane'].open_perf_buffer(
                packet_cp_callback)
        if log_cp_callback:
            self.__startup['log_buffer'].open_perf_buffer(log_cp_callback)

        # Starting daemon process to poll perf buffers for messages
        if packet_cp_callback or log_cp_callback:
            def poll():
                try:
                    while True:
                        self.__startup.perf_buffer_poll()
                except Exception:
                    pass
            threading.Thread(target=poll, daemon=True).start()

        atexit.register(lambda: EbpfCompiler().__del__()
                        if EbpfCompiler() else None)

    def __del__(self):
        if self.__is_destroyed:
            return
        self.__is_destroyed = True
        # Remove only once all kind of eBPF programs attached to all interfaces in use.
        with IPRoute() as ip:
            ip.link("del", ifname="DeChainy")
            for idx in self.__interfaces_programs.keys():
                EbpfCompiler.__logger.info('Removing all programs from Interface Index {}'.format(
                    self.__interfaces_programs[idx].name))
                with self.__interfaces_programs[idx].ingress_xdp.lock, self.__interfaces_programs[idx].egress_xdp.lock:
                    if self.__interfaces_programs[idx].ingress_xdp.programs or \
                            self.__interfaces_programs[idx].egress_xdp.programs:
                        BPF.remove_xdp(
                            self.__interfaces_programs[idx].name, self.__interfaces_programs[idx].flags)
                with self.__interfaces_programs[idx].ingress_tc.lock,\
                        self.__interfaces_programs[idx].egress_tc.lock:
                    if self.__interfaces_programs[idx].ingress_tc.programs or \
                            self.__interfaces_programs[idx].egress_tc.programs:
                        ip.tc("del", "clsact", idx)

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
        with open(f'{EbpfCompiler.__base_dir}/pivoting.c', 'r') as fp:
            pivoting_code = remove_c_comments(fp.read())\
                .replace('PROGRAM_TYPE', program_type)\
                .replace('MODE', EbpfCompiler.__TC_MAP_SUFFIX if mode == BPF.SCHED_CLS or program_type == "egress"
                         else EbpfCompiler.__XDP_MAP_SUFFIX)

        EbpfCompiler.__logger.info(
            'Compiling Pivot for Interface {} Type {} Mode {}'.format(interface, program_type, mode_map_name))

        # Compiling the eBPF program
        p = Program(interface=interface, idx=idx, mode=mode, code=pivoting_code, cflags=EbpfCompiler.__formatted_cflags(
            mode, program_type), debug=False, flags=flags, program_id=0, offload_device=offload_device)
        target = getattr(
            self.__interfaces_programs[idx], f'{program_type}_{mode_map_name}')
        with target.lock:
            if mode == BPF.XDP:
                BPF.attach_xdp(interface, p.f, flags=flags)
            else:
                with IPRoute() as ip:
                    # Checking if already created the class act for the interface
                    if not getattr(self.__interfaces_programs[idx], f'ingress_{mode_map_name}').programs \
                            and not getattr(self.__interfaces_programs[idx], f'egress_{mode_map_name}').programs:
                        ip.tc("add", "clsact", idx)
                    ip.tc("add-filter", "bpf", idx, ':1', fd=p.f.fd, name=p.f.name,
                          parent=parent, classid=1, direct_action=True)
            target.programs.insert(0, p)

    def remove_hook(self, program_type, program: Union[Program, SwapStateCompile]):
        """Method to remove the programs associated to a specific probe

        Args:
            conf (Union[ProbeCompilation, SwapStateCompile]): The object containing the programs
        """
        tmp = program if not isinstance(
            program, SwapStateCompile) else program._programs[0]
        mode_map_name = EbpfCompiler.__TC_MAP_SUFFIX if tmp.mode == BPF.SCHED_CLS else EbpfCompiler.__XDP_MAP_SUFFIX
        next_map_name = f'{program_type}_next_{mode_map_name}'
        type_of_interest = f'{program_type}_{mode_map_name}'
        target = getattr(
            self.__interfaces_programs[tmp.idx], type_of_interest)

        with target.lock:
            # Retrieving the index of the Program retrieved
            index = target.programs.index(program)
            program = tmp
            EbpfCompiler.__logger.info('Deleting Program {} Interface {} Type {}'.format(
                program.program_id, program.interface, program_type))

            target.ids.append(target.programs[index].program_id)

            # Checking if only two programs left into the interface, meaning
            # that also the pivoting has to be removed
            if len(target.programs) == 2:
                EbpfCompiler.__logger.info('Deleting Also Pivot Program')
                [x.__del__() for x in reversed(target.programs)]
                target.programs.clear()
                # Checking if also the class act or the entire XDP program can be removed
                if not getattr(self.__interfaces_programs[program.idx], '{}_{}'.format(
                        "egress" if program_type == "ingress" else "ingress", mode_map_name)).programs:
                    if program.mode == BPF.SCHED_CLS:
                        with IPRoute() as ip:
                            ip.tc("del", "clsact", program.idx)
                    else:
                        BPF.remove_xdp(program.interface, program.flags)
                    del self.__interfaces_programs[tmp.idx]
                return

            if index + 1 != len(target.programs):
                # The program is not the last one in the list, so
                # modify program CHAIN in order that the previous program calls the
                # following one instead of the one to be removed
                target.programs[0][next_map_name][target.programs[index -
                                                                  1].program_id] = ct.c_int(target.programs[index + 1].f.fd)
                del target.programs[0][next_map_name][program.program_id]
            else:
                # The program is the last one in the list, so set the previous
                # program to call the following one which will be empty
                del target.programs[0][next_map_name][target.programs[index-1].program_id]
            target.programs[index].__del__()
            del target.programs[index]

    def compile_hook(self, program_type, code, interface, mode, flags, cflags, debug, plugin_id, probe_id, log_level):
        try:
            with IPRoute() as ip:
                idx = ip.link_lookup(ifname=interface)[0]
        except IndexError:
            raise exceptions.UnknownInterfaceException(
                'Interface {} not available'.format(interface))

        # Retrieve eBPF values given Mode and program type
        mode, flags, offload_device, mode_map_name, parent = EbpfCompiler.__ebpf_values(
            mode, flags, interface, program_type)

        # Checking if the interface has already been used so there's already
        # Holder structure
        if idx not in self.__interfaces_programs:
            self.__interfaces_programs[idx] = InterfaceHolder(
                interface, flags, offload_device)
        elif program_type == "ingress":
            flags, offload_device = self.__interfaces_programs[
                idx].flags, self.__interfaces_programs[idx].offload_device

        program_chain = getattr(
            self.__interfaces_programs[idx], f'{program_type}_{mode_map_name}')
        with program_chain.lock:
            # If the array representing the hook is empty, inject the pivot code
            if not program_chain.programs:
                self.__inject_pivot(mode, flags, offload_device,
                                    interface, idx, program_type, mode_map_name, parent)
            program_id = program_chain.ids.pop(0)
            EbpfCompiler.__logger.info(
                'Compiling Program {} Interface {} Type {} Mode {}'.format(program_id, interface, program_type, mode_map_name))

            original_code, swap_code, features = EbpfCompiler.__precompile_parse(
                EbpfCompiler.__format_for_hook(mode, program_type, EbpfCompiler.__format_helpers(code)))

            cflags = cflags + EbpfCompiler.__formatted_cflags(
                mode, program_type, program_id, plugin_id, probe_id, log_level)

            # Loading compiled "internal_handler" function and set the previous
            # plugin program to call in the CHAIN to the current function descriptor
            ret = Program(interface=interface, idx=idx, mode=mode, flags=flags, offload_device=offload_device,
                          cflags=cflags, debug=debug, code=original_code, program_id=program_id, features=features)

            # Updating Service Chain
            program_chain.programs[0][f'{program_type}_next_{mode_map_name}'][
                program_chain.programs[-1].program_id] = ct.c_int(ret.f.fd)

            # Compiling swap program if needed
            if swap_code:
                EbpfCompiler.__logger.info('Compiling Also Swap Code')
                p1 = Program(interface=interface, idx=idx, mode=mode, flags=flags, code=swap_code, debug=debug,
                             cflags=cflags, offload_device=offload_device, program_id=program_id, features=features)
                ret = SwapStateCompile(
                    [ret, p1], program_chain.programs[0][f'{program_type}_next_{mode_map_name}'])
            # Append the main program to the list of programs
            program_chain.programs.append(ret)
            return ret

    @staticmethod
    def __formatted_cflags(
            mode: int,
            program_type: str,
            program_id: int = 0,
            plugin_id: int = 0,
            probe_id: int = 0,
            log_level: int = logging.INFO) -> List[str]:
        """Function to return CFLAGS according to ingress/egress and TC/XDP

        Args:
            mode (int): The program mode (XDP or TC)
            program_type (str): The hook of the program (ingress/egress)
            program_id (int, optional): The ID of the program to be created. Defaults to 0.
            plugin_id (int, optional): The ID of the plugin. Defaults to 0.
            probe_id (int, optional): The ID of the probe within the plugin. Defaults to 0.
            log_level (int, optional): The Log Level of the probe. Defaults to logging.INFO.

        Returns:
            List[str]: The list of computed cflags
        """
        return EbpfCompiler.__DEFAULT_CFLAGS + \
            (EbpfCompiler.__TC_CFLAGS if mode == BPF.SCHED_CLS else EbpfCompiler.__XDP_CFLAGS) + \
            [f'-DPROGRAM_ID={program_id}', f'-DPLUGIN_ID={plugin_id}',
             f'-DINGRESS={1 if program_type == "ingress" else 0}',
             f'-DPROBE_ID={probe_id}', f'-DLOG_LEVEL={log_level}']

    @staticmethod
    def __ebpf_values(mode: int, flags: int, interface: str, program_type: str) -> Tuple[int, int, str, str, str]:
        """Function to return BPF map values according to ingress/egress and TC/XDP

        Args:
            mode (int): The program mode (XDP or TC)
            flags (int): Flags to be used in the mode
            interface (str): The interface to which attach the program
            program_type (str): The program hook (ingress/egress)

        Returns:
            Tuple[int, int, str str, str]: The values representing the mode, the suffix for maps names and parent interface
        """
        if program_type == "egress":
            return BPF.SCHED_CLS, 0, None, EbpfCompiler.__TC_MAP_SUFFIX, EbpfCompiler.__PARENT_EGRESS_TC
        if mode == BPF.SCHED_CLS:
            return BPF.SCHED_CLS, 0, None, EbpfCompiler.__TC_MAP_SUFFIX, EbpfCompiler.__PARENT_INGRESS_TC
        return BPF.XDP, flags, interface if flags == (1 << 3) else None, EbpfCompiler.__XDP_MAP_SUFFIX, None

    @staticmethod
    def __precompile_parse(original_code: str) -> Tuple[str, str, Dict[str, MetricFeatures]]:
        """Function to compile additional functionalities from original code (swap, erase, and more)

        Args:
            original_code (str): The original code to be controlled

        Returns:
            Tuple[str, str, Dict[str, MetricFeatures]]: Only the original code if no swaps maps,
                else the tuple containing also swap code and list of metrics configuration
        """
        # Find map declarations, from the end to the beginning
        declarations = [(m.start(), m.end(), m.group()) for m in finditer(
            r"^(BPF_TABLE|BPF_QUEUESTACK|BPF_PERF).*$", original_code, MULTILINE)]
        declarations.reverse()

        # Check if at least one map needs swap
        need_swap = any(x for _, _, x in declarations if "__attributes__" in x and "SWAP" in x.split(
            "__attributes__")[1])
        cloned_code = original_code if need_swap else None

        maps = {}
        for start, end, declaration in declarations:
            new_decl, splitted = declaration, declaration.split(',')
            map_name = splitted[1].split(")")[0].strip() if (
                "BPF_Q" in declaration or "BPF_P" in declaration) else splitted[3].split(")")[0].strip()

            # Check if this declaration has some attribute
            if "__attributes__" in declaration:
                tmp = declaration.split("__attributes__")
                new_decl = tmp[0] + ";"
                maps[map_name] = MetricFeatures(
                    swap="SWAP" in tmp[1], export="EXPORT" in tmp[1], empty="EMPTY" in tmp[1])

            orig_decl = new_decl

            # If need swap and this map doesn't, then perform changes in declaration
            if need_swap and (map_name not in maps or not maps[map_name].swap):
                tmp = splitted[0].split('(')
                prefix_decl = tmp[0]
                map_type = tmp[1]
                if prefix_decl.count("_") <= 1:
                    if "extern" not in map_type:
                        new_decl = new_decl.replace(map_type, '"extern"')
                        index = len(prefix_decl)
                        orig_decl = orig_decl[:index] + \
                            "_SHARED" + orig_decl[index:]
                else:
                    new_decl = new_decl.replace(map_type, '"extern"').replace(
                        prefix_decl, '_'.join(prefix_decl.split("_")[:2]))

            original_code = original_code[:start] + \
                orig_decl + original_code[end:]
            if cloned_code:
                cloned_code = cloned_code[:start] + \
                    new_decl + cloned_code[end:]

        for map_name, features in maps.items():
            if features.swap:
                cloned_code = cloned_code.replace(map_name, f"{map_name}_1")
        return original_code, cloned_code, maps

    @staticmethod
    def __format_for_hook(
            mode: int,
            program_type: str,
            code: str) -> str:
        """Function to return the probe wrapper code according to ingress/egress, TC/XDP, and substitute dp_log function

        Args:
            mode (int): The program mode (XDP or TC)
            program_type (str): The program hook (ingress/egress)
            code (str, optional): The code to be formatted

        Returns:
            str: The code formatted accordingly
        """
        return code.replace('PROGRAM_TYPE', program_type)\
            .replace('MODE', EbpfCompiler.__TC_MAP_SUFFIX if mode == BPF.SCHED_CLS or program_type == "egress"
                     else EbpfCompiler.__XDP_MAP_SUFFIX)

    @staticmethod
    def __format_helpers(code: str) -> str:
        # Removing C-like comments
        code = remove_c_comments(code)

        declarations = [(m.start(), m.end(), m.group()) for m in finditer(
            r"return REDIRECT\((.*)\);.*$", code, MULTILINE)]
        declarations.reverse()

        # sub REDIRECT <interface> with proper code
        with IPRoute() as ip:
            for start, end, declaration in declarations:
                try:
                    idx = ip.link_lookup(ifname=declaration)[0]
                    code = code[:start] + 'u32 index = {}; return bpf_redirect(&index, 0);'.format(
                        idx) + code[end:]
                except IndexError:
                    raise exceptions.UnknownInterfaceException(
                        f'Interface {declaration} not available')

        # Finding dp_log function invocations if any, and reverse to avoid bad
        # indexes while updating
        matches = [(m.start(), m.end()) for m in finditer('dp_log.*;', code)]
        matches.reverse()
        for start, end in matches:
            # Getting the log level specified
            log_level = code[start + 7: end].split(",")[0]
            # Substitute the dp_log invocation (length 6 characters) with the right
            # logging function
            code = code[:start] \
                + f'if ({log_level} <= LOG_LEVEL)' \
                + '{LOG_STRUCT' \
                + code[start + 6:end] \
                + 'log_buffer.perf_submit(ctx, &msg_struct, sizeof(msg_struct));}' \
                + code[end:]
        with open(f'{EbpfCompiler.__base_dir}/helpers.h', 'r') as fp,\
                open(f'{EbpfCompiler.__base_dir}/wrapper.c', 'r') as fp1:
            helpers_code = remove_c_comments(fp.read())
            wrapper_code = remove_c_comments(fp1.read())
        return helpers_code + wrapper_code + code

    @staticmethod
    def is_batch_supp() -> bool:
        """Function to check whether the batch operations are supported for this system (kernel >= v5.6)

        Returns:
            bool: True if they are supported, else otherwise
        """
        if EbpfCompiler.__is_batch_supp is None:
            major, minor = [int(x) for x in run(
                ['uname', '-r'], stdout=PIPE).stdout.decode('utf-8').split('.')[:2]]
            EbpfCompiler.__is_batch_supp = True if major > 5 or (
                major == 5 and minor >= 6) else False
        return EbpfCompiler.__is_batch_supp
