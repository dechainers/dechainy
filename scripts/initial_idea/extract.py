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
import errno
import ctypes as ct
import numpy as np

from typing import Dict, List, OrderedDict, Tuple
from socket import ntohs, inet_ntoa
from subprocess import run, PIPE
from multiprocessing.pool import ThreadPool
from bcc import lib, BPF
from keras.models import load_model


# Batch size for map retrieval
__BATCH_SIZE = 10000

# Packets per flow, used when training model
__MAX_FLOW_LEN = 10

# Pool holding async tasks
__pool = ThreadPool(processes=1)

# NN Model, if any
__model = None

# Dictionary of features extracted
__feature_list = OrderedDict([
    ('timestamp', [0, None]),
    ('IP_flags', [0, 65535]),
    ('TCP_flags', [0, 65535]),
    ('TCP_window_size', [0, 65535]),
    ('UDP_length', [0, 65535]),
    ('ICMP_type', [0, 255])]
)

# Values for normalization
__rng = None
__maxs = None

# Map holding the string representation of the protocol, given its value
__protocol_map = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}

# Variable to check whether Batch operations are supported
__major, __minor = [int(x) for x in run(['uname', '-r'], stdout=PIPE).stdout.decode('utf-8').split('.')[:2]]
__is_batch_supp = True if __major > 5 or (__major == 5 and __minor >= 6) else False


def __normalize_and_padding(samples: List[List[any]], high: float = 1.0, low: float = 0.0) -> np.array:
    """Function to normalize and pad the retrieved packets

    Args:
        samples (List[List[any]]): List of packets per session
        high (float, optional): Upper bound of normalization. Defaults to 1.0.
        low (float, optional): Lower bound of normalization. Defaults to 0.0.

    Returns:
        np.array: The array of flows normalized and padded
    """
    global __MAX_FLOW_LEN, __maxs, __rng
    normalized_samples = []
    for sample in samples:
        # if the sample is bigger than expected, we cut the sample
        if sample.shape[0] > __MAX_FLOW_LEN:
            sample = sample[:__MAX_FLOW_LEN, ...]
        # scale to linear bicolumn
        norm_sample = high - (((high - low) * (__maxs - sample)) / __rng)
        # padding
        norm_sample = np.pad(norm_sample, ((
            0, __MAX_FLOW_LEN - sample.shape[0]), (0, 0)), 'constant', constant_values=(0, 0))
        normalized_samples.append(norm_sample)
    return np.array(normalized_samples)


def __extract_sessions_batch(program: BPF) -> Dict[Tuple[str, int, str, int, int], Tuple[int]]:
    """Function to extract values from sessions map using eBPF batch operations

    Args:
        program (BPF): The eBPF compiled program

    Returns:
        Dict[Tuple[str,int,str,int,int], Tuple[int]]: Dictionary with session ID as key, and tuple holding
            information concerning the session
    """
    global __BATCH_SIZE
    flows = {}
    ret = 0
    batch = ct.c_ulonglong(0)
    count = ct.c_int(__BATCH_SIZE)
    keys = (program["SESSIONS_TRACKED_DDOS"].Key * __BATCH_SIZE)()
    values = (program["SESSIONS_TRACKED_DDOS"].Leaf * __BATCH_SIZE)()
    while not ret:
        # Keep extracting+deleting values untill the map is empty
        count = ct.c_int(__BATCH_SIZE)
        ret, last_errno = lib.bpf_map_lookup_and_delete_batch(
            program["SESSIONS_TRACKED_DDOS"].get_fd(),
            ct.byref(batch), ct.byref(batch), keys, values, ct.byref(count), None), ct.get_errno()
        if ret == 0 or (count.value != 0 and last_errno == errno.ENOENT):
            for i in range(count.value):
                key = keys[i]
                val = values[i]
                flow_id = (key.saddr, key.sport,
                           key.daddr, key.dport, key.proto)
                flows[flow_id] = (val.server_ip, val.n_packets)
    return flows


def __extract_sessions_normal(program: BPF) -> Dict[Tuple[str, int, str, int, int], Tuple[int]]:
    """Function to extract values from sessions map using eBPF sequential lookups

    Args:
        program (BPF): The eBPF compiled program

    Returns:
        Dict[Tuple[str,int,str,int,int], Tuple[int]]: Dictionary with session ID as key, and tuple holding
            information concerning the session
    """
    flows = {}
    for key, val in program["SESSIONS_TRACKED_DDOS"].items():
        flow_id = (key.saddr, key.sport, key.daddr, key.dport, key.proto)
        flows[flow_id] = (val.server_ip, val.n_packets)
        del program["SESSIONS_TRACKED_DDOS"][key]
    return flows


def __extract_packets(program: BPF) -> Dict[Tuple[str, int, str, int, int], np.array]:
    """Function called asynchronously to retrieve all packets from the queue.
    Unfortunately, queue does not support batch operation, so iterative functions are used.


    Args:
        program (BPF): The eBPF compiled program

    Returns:
        Dict[Tuple[str,int,str,int,int], np.array]: Dictionary with session ID as key, and tuple holding
            the list of packets for that session
    """
    flows = {}
    while True:
        try:
            val = program["PACKET_BUFFER_DDOS"].pop()
            features = [val.timestamp / 1000000000, val.ipFlagsFrag,
                        val.tcpFlags, val.tcpWin, val.udpSize, val.icmpType]
            flow_id = (val.id.saddr, val.id.sport,
                       val.id.daddr, val.id.dport, val.id.proto)
            if flow_id in flows:
                flows[flow_id].append(features)
            else:
                flows[flow_id] = [features]
        except KeyError:
            break
    for key, value in flows.items():
        # Subtract 1st timestamp to all, in order to normalize the value betwenn 0 and TIME_WINDOW
        start_time = value[0][0]
        np_sample = np.array(value)
        np_sample[:, 0] -= start_time
        flows[key] = np_sample
    return flows


def read_program_maps(program: BPF):
    """Function called whenever the time window expires, to retrieve values from eBPF maps

    Args:
        program (BPF): The compiled eBPF program
    """
    global __pool, __model

    # Extract asynchronously from the Queue
    async_result = __pool.apply_async(__extract_packets, (program,))

    checkpoint_0 = time.time()

    # Extract from the Hash map
    flows = __extract_sessions_batch(
        program) if __is_batch_supp else __extract_sessions_normal(program)

    # While waiting for the Queue to be extracted, parse Sessions IDs into human-readable
    ids_list = []
    for key, value in flows.items():
        correct_key = key
        if key[0] == value[0]:
            correct_key = (key[2], key[3], key[0], key[1], key[4])
        ids_list.append((
            inet_ntoa(correct_key[0].to_bytes(4, 'little')),
            ntohs(correct_key[1]),
            inet_ntoa(correct_key[2].to_bytes(4, 'little')),
            ntohs(correct_key[3]),
            __protocol_map[correct_key[4]]
        ))

    packets_map = async_result.get()
    checkpoint_1 = time.time()

    if not packets_map:
        print("\tNo packets has been retrieved", flush=True)
        return

    # Perform conversion, normalization and padding
    packets_list = [packets_map[key] for key in flows.keys()]
    packets_list = __normalize_and_padding(packets_list)
    packets_list = np.expand_dims(packets_list, axis=3)
    checkpoint_3 = time.time()

    if __model:
        # If provided, compute the prediction using the previously loaded NN module
        __model.predict(packets_list, batch_size=2048) > 0.5
    checkpoint_4 = time.time()

    print(f"\tPackets: {sum([len(x) for x in packets_map])}, Sessions: {len(ids_list)}, "
          f"Ebpf Time: {checkpoint_1 - checkpoint_0}, Prediction Time: {(checkpoint_4 - checkpoint_3) if __model else -1}",
          flush=True)


def init(model_path: str, time_window: int):
    """Init function to initialize module local variables

    Args:
        model_path (str): The path to the model
        time_window (int): The time window used, define in the main
    """
    global __feature_list, __rng, __maxs, __model
    try:
        __model = load_model(model_path)
    except ImportError:
        pass
    __feature_list["timestamp"][1] = time_window
    __rng = np.array([x[1] - x[0] for x in __feature_list.values()])
    __maxs = np.array([x[1] for x in __feature_list.values()])
