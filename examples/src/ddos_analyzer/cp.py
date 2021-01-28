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

###############################################################
# NB: Need the Docker image to be compiled with "ml" argument #
###############################################################
import time
import errno
import ctypes as ct
import numpy as np

from multiprocessing.pool import ThreadPool
from base64 import b64decode
from os.path import isfile
from collections import OrderedDict
from typing import Dict, Tuple
from bcc import lib
from bcc.table import QueueStack, TableBase
from keras.models import load_model

from dechainy.utility import ipv4_to_string, port_to_host_int, protocol_to_string
from dechainy.ebpf import is_batch_supp
from dechainy.plugins import Plugin

# pool with 1 thread used to perform async packets retrieval
pool = ThreadPool(processes=1)

# the Neural Network model
model = None

# range values of features (max - min) specified in feature_list
rng = None

# max values of features specified in feature_list
maxs = None

# max packets per flow
MAX_FLOW_LEN = 10

# size of a batch lookup+delete
BATCH_SIZE = 10000

# feature list with min and max values (None has to be set at runtime)
feature_list = OrderedDict([
    ('timestamp', [0, None]),
    ('IP_flags', [0, 65535]),
    ('TCP_flags', [0, 65535]),
    ('TCP_window_size', [0, 65535]),
    ('UDP_length', [0, 65535]),
    ('ICMP_type', [0, 255])]
)


def normalize_and_padding(samples: np.array, high: float = 1.0, low: float = 0.0) -> np.array:
    """Function to normalize the array of samples and add padding if needed

    Args:
        samples (np.array): The list of samples
        high (float, optional): The upper bound. Defaults to 1.0.
        low (float, optional): The lower bound. Defaults to 0.0.

    Returns:
        np.array: The list of normalized values
    """
    global MAX_FLOW_LEN, maxs, rng
    normalized_samples = []
    for sample in samples:
        # if the sample is bigger than expected, we cut the sample
        if sample.shape[0] > MAX_FLOW_LEN:
            sample = sample[:MAX_FLOW_LEN, ...]
        # scale to linear bicolumn
        norm_sample = high - (((high - low) * (maxs - sample)) / rng)
        # padding
        norm_sample = np.pad(norm_sample, ((
            0, MAX_FLOW_LEN - sample.shape[0]), (0, 0)), 'constant', constant_values=(0, 0))
        normalized_samples.append(norm_sample)
    return np.array(normalized_samples)


def extract_sessions_batch(table: TableBase) -> Dict[Tuple[str, int, str, int, int], Tuple[int]]:
    """Function to extract values from sessions map using eBPF batch operations

    Args:
        table (TableBase): The table of interest

    Returns:
        Dict[Tuple[str,int,str,int,int], Tuple[int]]: Dictionary with session ID as key, and tuple holding
            information concerning the session
    """
    flows = {}
    ret = 0
    batch = ct.c_ulonglong(0)
    count = ct.c_int(BATCH_SIZE)
    keys = (table.Key * BATCH_SIZE)()
    values = (table.Leaf * BATCH_SIZE)()
    while not ret:
        # Keep extracting+deleting values untill the map is empty
        count = ct.c_int(BATCH_SIZE)
        ret, last_errno = lib.bpf_map_lookup_and_delete_batch(
            table.get_fd(),
            ct.byref(batch), ct.byref(batch), keys, values, ct.byref(count), None), ct.get_errno()
        if ret == 0 or (count.value != 0 and last_errno == errno.ENOENT):
            for i in range(count.value):
                key = keys[i]
                val = values[i]
                flow_id = (key.saddr, key.sport,
                           key.daddr, key.dport, key.proto)
                flows[flow_id] = (val.server_ip, val.n_packets)
    return flows


def extract_sessions_normal(table: TableBase) -> Dict[Tuple[str, int, str, int, int], Tuple[int]]:
    """Function to extract values from sessions map using eBPF sequential lookups

    Args:
        table (TableBase): The table of interest

    Returns:
        Dict[Tuple[str,int,str,int,int], Tuple[int]]: Dictionary with session ID as key, and tuple holding
            information concerning the session
    """
    flows = {}
    for key, val in table.items():
        flow_id = (key.saddr, key.sport, key.daddr, key.dport, key.proto)
        flows[flow_id] = (val.server_ip, val.n_packets)
        del table[key]
    return flows


def extract_packets(queue: QueueStack) -> Dict[Tuple[str, int, str, int, int], np.array]:
    """Function called asynchronously to retrieve all packets from the queue.
    Unfortunately, queue does not support batch operation, so iterative functions are used.

    Args:
        queue (QueueStack): The queue of interest

    Returns:
        Dict[Tuple[str,int,str,int,int], np.array]: Dictionary with session ID as key, and tuple holding
            the list of packets for that session
    """
    flows = {}
    while True:
        try:
            val = queue.pop()
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
        start_time = value[0][0]
        np_sample = np.array(value)
        np_sample[:, 0] -= start_time
        flows[key] = np_sample
    return flows


def reaction_function_rest(probe: Plugin) -> Dict[str, any]:
    """Function called via REST interaction

    Args:
        probe (Plugin): The probe of interest

    Returns:
        Dict[str, any]: Dictionary containing times and results of prediction
    """
    global model

    checkpoint_0 = time.time()

    probe["ingress"].trigger_read()
    probe["egress"].trigger_read()

    # Extract asynchronously from the Queue
    async_result = pool.apply_async(
        extract_packets, (probe["ingress"]["PACKET_BUFFER_DDOS"],))

    checkpoint_1 = time.time()

    # Extract from the Hash map
    flows = extract_sessions_batch(
        probe["ingress"]["SESSIONS_TRACKED_DDOS"]) if is_batch_supp() \
        else extract_sessions_normal(probe["ingress"]["SESSIONS_TRACKED_DDOS"])

    ids_list = []
    # While waiting for the Queue to be extracted, parse Sessions IDs into human-readable
    for key, value in flows.items():
        correct_key = key
        if key[0] == value[0]:
            correct_key = (key[2], key[3], key[0], key[1], key[4])
        ids_list.append((
            ipv4_to_string(correct_key[0]),
            port_to_host_int(correct_key[1]),
            ipv4_to_string(correct_key[2]),
            port_to_host_int(correct_key[3]),
            protocol_to_string(correct_key[4])
        ))

    packets_map = async_result.get()
    checkpoint_2 = time.time()

    if not packets_map:
        return None

    # Perform conversion, normalization and padding
    packets_list = [packets_map[key] for key in flows.keys()]
    packets_list = normalize_and_padding(packets_list)
    packets_list = np.expand_dims(packets_list, axis=3)
    checkpoint_3 = time.time()
    predictions = model.predict(packets_list, batch_size=2048) > 0.5
    checkpoint_4 = time.time()
    return {"flows": [x + (p[0],) for x, p in zip(ids_list, predictions)],
            "total_time": checkpoint_4 - checkpoint_0, "controls_time": checkpoint_1 - checkpoint_0,
            "prediction_time": checkpoint_4 - checkpoint_3, "ebpf_time": checkpoint_2 - checkpoint_1,
            "numpy_time": checkpoint_3 - checkpoint_2, "total_pkts": packets_list.shape[1] * packets_list.shape[0],
            "ebpf_pkts": sum([len(x) for x in packets_map]), "total_sessions": len(ids_list)}


def reaction_function(probe: Plugin):
    ret = reaction_function_rest(probe)
    if ret:
        print(
            'Got something!\n\t'
            f'TIME total: {ret["total_time"]} (s)\n\t'
            f'TIME controls: {ret["controls_time"]}\n\t'
            f'TIME ebpf extraction + parse: {ret["ebpf_time"]} (s)\n\t'
            f'TIME numpy padding and normalize: {ret["numpy_time"]} (s)\n\t'
            f'TIME prediction: {ret["prediction_time"]} (s)\n\t'
            f'Total Sessions: {ret["total_sessions"]}\n\t'
            f'Total Packets: {ret["total_pkts"]}'
            f'Total Packets not padded: {ret["ebpf_pkts"]}', flush=True)
    else:
        print('Got nothing!', flush=True)


def setup(probe: Plugin):
    global model, maxs, rng, feature_list

    if 'model' not in probe._config.files:
        raise Exception("No Model has been specified")

    path = probe._config.files['model']
    if not isfile(path):
        content = path
        path = "/tmp/model"
        with open(path, "wb+") as fp:
            fp.write(b64decode(content))
    model = load_model(path)

    feature_list['timestamp'][1] = probe._config.time_window
    rng = np.array([x[1] - x[0] for x in feature_list.values()])
    maxs = np.array([x[1] for x in feature_list.values()])
