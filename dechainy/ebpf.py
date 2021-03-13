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
import time
import ctypes as ct
from enum import Enum

from os.path import dirname
from re import finditer, MULTILINE
from subprocess import run, PIPE
from typing import List, Tuple, Union
from bcc import BPF
from bcc.table import QueueStack, TableBase
from atexit import unregister

from .utility import remove_c_comments


class Metadata(ct.Structure):
    """C struct representing the pkt_metadata structure in Data Plane programs

    Attributes:
        ifindex (c_uint32): The interface on which the packet was received
        ptype (c_uint32): The program type ingress/egress
        probe_id (c_uint64): The ID of the probe
    """
    _fields_ = [("ifindex", ct.c_uint32),
                ("ptype", ct.c_uint32),
                ("probe_id", ct.c_uint64)]


class LpmKey(ct.Structure):
    """C struct representing the LPM_KEY

    Attributes:
        netmask_len (c_uint32): the length of the netmask
        ip (c_uint32): the ip specified
    """
    _fields_ = [("netmask_len", ct.c_uint32),
                ("ip", ct.c_uint32)]


class Program:
    """Program class to handle both useful information and BPF program.

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
        red_idx (int): Index of the interface packets are redirect, if needed
        is_destroyed (bool): Boolean value set to True when the instance is destroyed
    """

    def __init__(
            self,
            interface: str,
            idx: int,
            mode: int,
            bpf: BPF,
            fd: int = None,
            probe_id: int = 0,
            red_idx: int = 0):
        self.interface = interface
        self.idx = idx
        self.mode = mode
        self.fd = fd
        self.probe_id = probe_id
        self.red_idx = red_idx
        self.__bpf = bpf
        self.__is_destroyed = False
        if red_idx:
            self.__bpf["DEVMAP"][ct.c_uint32(0)] = ct.c_int(red_idx)

    def __del__(self):
        if self.__is_destroyed:
            return
        # Calling the BCC defined cleanup function which would have been
        # called while exitting
        self.__is_destroyed = True
        unregister(self.__bpf.cleanup)
        self.__bpf.cleanup()
        del self.__bpf

    def __getitem__(self, key: str) -> Union[QueueStack, TableBase]:
        """Function to access directly the BPF map providing a key

        Args:
            key (str): The name of the map

        Returns:
            Union[QueueStack, TableBase]: The eBPF map requested
        """
        return self.__bpf[key] if not self.__is_destroyed else exit(1)


class SwapStateCompile:
    """Class storing the state of a program when the SWAP of at least 1 map is required.

    Args:
        programs (List[Program]): The list of the two compiled programs
        pivot (Program): The pivoting eBPF program compiled
        maps (List[str]): The list of maps defined as swappable

    Attributes:
        maps (List[str]): The maps defined as swappable
        index (int): The index of the current active program
        programs (List[Program]): The list containing the two programs compiled
        pivot (Program): The pivoting eBPF program compiled
    """

    def __init__(self, programs: List[Program], pivot: Program, maps: List[str]):
        self.__is_destroyed = False
        self.__maps: List[str] = maps
        self.__index: int = 0
        self.__programs: List[Program] = programs
        self.__pivot: Program = pivot
        self.__pivot['ACTIVE_PROGRAM'][0] = ct.c_int(
            self.__programs[self.__index].fd)

    def __del__(self):
        if self.__is_destroyed:
            return
        self.__is_destroyed = True
        del self.__programs[0]
        del self.__programs[1]
        self.__programs = []

    def trigger_read(self):
        """Method to trigger the read of the maps, meaning to swap in and out the programs"""
        if self.__is_destroyed:
            exit(1)
        self.__index = (self.__index + 1) % 2
        self.__pivot['ACTIVE_PROGRAM'][0] = ct.c_int(
            self.__programs[self.__index].fd)

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
        if index_to_read == 1 and key in self.__maps:
            key += "_1"
        return self.__programs[index_to_read][key]


class DPLogLevel(Enum):
    """Class to represent the log level of a datapath program."""
    LOG_OFF = 0
    LOG_INFO = 1
    LOG_DEBUG = 2
    LOG_WARN = 3
    LOG_ERR = 4


# Computing EPOCH BASE time from uptime, to synchronize bpf_ktime_get_ns()
with open('/proc/uptime', 'r') as f:
    __EPOCH_BASE = int(
        (int(time.time() * 10**9) - int(float(f.readline().split()[0]) * (10 ** 9))))

__base_dir = f'{dirname(__file__)}/sourcebpf/management'

# Variable to store startup code, containing the log buffer perf event map
with open(f'{__base_dir}/startup.h', 'r') as fp:
    __STARTUP = remove_c_comments(fp.read())

# Variable to store Pivoting code for all modes and perform chain
with open(f'{__base_dir}/pivoting.c', 'r') as fp:
    __PIVOTING_CODE = remove_c_comments(fp.read())

# Variable to store wrapper code for TC probes, to perform chain
with open(f'{__base_dir}/wrapper.c', 'r') as fp:
    __WRAPPER_CODE = remove_c_comments(fp.read())

# Variable to store all functions and parameters useful in all programs
with open(f'{__base_dir}/helpers.h', 'r') as fp:
    __HELPERS = remove_c_comments(fp.read())

# Variable to store the pivoting code for swap programs
with open(f'{__base_dir}/swap.c', 'r') as fp:
    __SWAP = remove_c_comments(fp.read())


# Variable to specify whether batch ops are supported (kernel >= v5.6)
__is_batch_supp = None

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
__PARENT_INGRESS_TC = 'ffff:fff2'
__PARENT_EGRESS_TC = 'ffff:fff3'
__XDP_MAP_SUFFIX = 'xdp'
__TC_MAP_SUFFIX = 'tc'
__MAX_PROGRAMS_PER_HOOK = 32

__TC_CFLAGS = [
    f'-DCTXTYPE={BPF.TC_STRUCT}',
    f'-DPASS={BPF.TC_ACT_OK}',
    f'-DDROP={BPF.TC_ACT_SHOT}',
    f'-DREDIRECT={BPF.TC_REDIRECT}']

__XDP_CFLAGS = [
    f'-DCTXTYPE={BPF.XDP_STRUCT}',
    f'-DBACK_TX={BPF.XDP_TX}',
    f'-DPASS={BPF.XDP_PASS}',
    f'-DDROP={BPF.XDP_DROP}',
    f'-DREDIRECT={BPF.XDP_REDIRECT}',
    '-DXDP=1']

__DEFAULT_CFLAGS = [
    "-w",
    f'-DMAX_PROGRAMS_PER_HOOK={__MAX_PROGRAMS_PER_HOOK}',
    f'-DEPOCH_BASE={__EPOCH_BASE}'] + [f'-D{x.name}={x.value}' for x in list(DPLogLevel)]


def get_swap_pivot() -> str:
    """Function to return the swap pivoting code

    Returns:
        str: The swap pivoting code
    """
    return __SWAP


def get_startup_code() -> str:
    """Function to return the startup code for the entire framework

    Returns:
        str: The startup code
    """
    return __STARTUP


def get_pivoting_code(mode: int, program_type: str) -> str:
    """Function to return the pivoting code according to ingress/egress and TC/XDP

    Args:
        mode (int): The program mode (XDP or TC)
        program_type (str): The program hook (ingress/egress)

    Returns:
        str: The pivoting code for the hook
    """
    ret = __PIVOTING_CODE.replace('PROGRAM_TYPE', program_type)
    if mode == BPF.SCHED_CLS or program_type == "egress":
        return ret.replace('MODE', __TC_MAP_SUFFIX)
    return ret.replace('MODE', __XDP_MAP_SUFFIX)


def get_formatted_code(
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
    if not code:
        return ''
    # Removing C-like comments
    cloned = remove_c_comments(code)
    # Finding dp_log function invocations if any, and reverse to avoid bad
    # indexes while updating
    matches = [(m.start(), m.end())
               for m in finditer('dp_log.*;', cloned)]
    matches.reverse()
    for start, end in matches:
        # Getting the log level specified
        log_level = cloned[start + 7: end].split(",")[0]
        # Substitute the dp_log invocation (length 6 characters) with the right
        # logging function
        cloned = cloned[:start] \
            + f'if ({log_level} >= LOG_LEVEL)' \
            + '{LOG_STRUCT' \
            + cloned[start + 6:end] \
            + 'log_buffer.perf_submit(ctx, &msg_struct, sizeof(msg_struct));}' \
            + cloned[end:]
    return __HELPERS + __WRAPPER_CODE .replace(
        'PROGRAM_TYPE',
        program_type) .replace(
        'MODE',
        __TC_MAP_SUFFIX if mode == BPF.SCHED_CLS or program_type == "egress" else __XDP_MAP_SUFFIX) + cloned


def get_bpf_values(mode: int, flags: int, interface: str, program_type: str) -> Tuple[int, int, str, str, str]:
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
        return BPF.SCHED_CLS, 0, None, __TC_MAP_SUFFIX, __PARENT_EGRESS_TC
    if mode == BPF.SCHED_CLS:
        return BPF.SCHED_CLS, 0, None, __TC_MAP_SUFFIX, __PARENT_INGRESS_TC
    return BPF.XDP, flags, interface if flags == (1 << 3) else None, __XDP_MAP_SUFFIX, None


def get_cflags(
        mode: int,
        program_type: str,
        probe_id: int = 0,
        log_level: int = DPLogLevel.LOG_INFO) -> List[str]:
    """Function to return CFLAGS according to ingress/egress and TC/XDP

    Args:
        mode (int): The program mode (XDP or TC)
        program_type (str): The hook of the program (ingress/egress)
        probe_id (int, optional): The ID of the probe to be created. Defaults to 0.
        log_level (int, optional): The Log Level of the probe. Defaults to DPLogLevel.LOG_INFO.

    Returns:
        List[str]: The list of computed cflags
    """
    return [f'-DPROBE_ID={probe_id}', f'-DPTYPE={0 if program_type == "ingress" else 1}', f'-DLOG_LEVEL={log_level.value}'] \
        + __DEFAULT_CFLAGS \
        + (__TC_CFLAGS if mode == BPF.SCHED_CLS else __XDP_CFLAGS)


def swap_compile(original_code: str) -> Tuple[str, str, str]:
    """Function to compile, if required, the original code in order to perform
    swap of eBPF maps.

    Args:
        original_code (str): The original code to be controlled

    Returns:
        Tuple[str]: Only the original code if no swaps maps, else the tuple containing
            also swap code and list of swappable maps
    """
    if original_code.find("__attribute((SWAP))") == -1:
        return original_code, None, None

    cloned_code = original_code

    declarations = [(m.start(), m.end(), m.group()) for m in finditer(
        r"^(BPF_TABLE|BPF_QUEUESTACK).*$", original_code, MULTILINE)]
    declarations.reverse()

    maps = []
    for start, end, declaration in declarations:
        splitted = declaration.split(',')
        map_name = splitted[1].strip(
        ) if "BPF_Q" in declaration else splitted[3].strip()
        if "__attribute((SWAP))" not in declaration:
            tmp = splitted[0].split('(')
            prefix_decl = tmp[0]
            map_type = tmp[1]
            new_decl = declaration.replace(map_type, '"extern"')
            if "BPF_TABLE_" in prefix_decl:  # shared/public/pinned
                new_decl = new_decl.replace(prefix_decl, "BPF_TABLE")
            elif "BPF_QUEUESTACK_" in prefix_decl:  # shared/public/pinned
                new_decl = new_decl.replace(prefix_decl, "BPF_QUEUESTACK")
            else:
                original_code = original_code[:start + 9] + \
                    "_SHARED" + original_code[start + 9:]
            cloned_code = cloned_code[:start] + new_decl + cloned_code[end:]
        elif map_name not in maps:
            maps.append(map_name)

    for map_name in maps:
        cloned_code = cloned_code.replace(f'{map_name}', f'{map_name}_1')
    original_code = original_code.replace('__attribute((SWAP))', '')
    cloned_code = cloned_code.replace('__attribute((SWAP))', '')
    return original_code, cloned_code, maps


def is_batch_supp() -> bool:
    """Function to check whether the batch operations are supported for this system (kernel >= v5.6)

    Returns:
        bool: True if they are supported, else otherwise
    """
    global __is_batch_supp
    if __is_batch_supp is None:
        major, minor = [int(x) for x in run(['uname', '-r'], stdout=PIPE).stdout.decode('utf-8').split('.')[:2]]
        __is_batch_supp = True if major > 5 or (major == 5 and minor >= 6) else False
    return __is_batch_supp
