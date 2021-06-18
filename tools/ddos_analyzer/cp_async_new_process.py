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
import os
import numpy as np

from multiprocessing.pool import ThreadPool
from multiprocessing import Process
from base64 import b64decode
from collections import OrderedDict
from typing import Dict
from itertools import groupby

from bcc.table import TableBase

from dechainy.utility import ipv4_to_string, port_to_host_int, protocol_to_string
from dechainy.ebpf import is_batch_supp
from dechainy.plugins import Plugin
from dechainy.configurations import ProbeConfig

# execution number
cnt = 0

# pool with 1 thread used to perform async session map erasion
pool = ThreadPool()

# the Neural Network model path
model_path = None

# range values of features (max - min) specified in feature_list
rng = None

# max values of features specified in feature_list
maxs = None

# max packets per flow
MAX_FLOW_LEN = None

# feature list with min and max values (None has to be set at runtime)
# NB: Keep the order as it is, it corresponds to the order of features in the trained model
#     The unused features are removed in setup.
feature_list = OrderedDict([
    ('timestamp', [0, None]),
    ('ip_flags', [0, 65535]),
    ('length', [0, 65535]),
    ('tcp_len', [0, 65535]),
    ('tcp_ack', [0, 1 << 32]),
    ('tcp_flags', [0, 65535]),
    ('tcp_win', [0, 65535]),
    ('udp_len', [0, 65535]),
    ('icmp_type', [0, 255])]
)


def async_prediction(packets,
                     exec_number,
                     checkpoint_0,
                     checkpoint_1,
                     checkpoint_2,
                     total_pkts_passed_from_sessions,
                     compute_ids=False):
    def normalize_and_padding_sample(sample: np.array, high: float = 1.0, low: float = 0.0) -> np.array:
        """Function to normalize a samples and add padding if needed
        Args:
            sample (np.array): A sample
            high (float, optional): The upper bound. Defaults to 1.0.
            low (float, optional): The lower bound. Defaults to 0.0.
        Returns:
            np.array: The normalized sample
        """
        global MAX_FLOW_LEN, maxs, rng, feature_list
        # if the sample is bigger than expected, we cut the sample
        if sample.shape[0] > MAX_FLOW_LEN:
            sample = sample[:MAX_FLOW_LEN, ...]
        if "timestamp" in feature_list:
            sample[:, 0] = (sample[:, 0] - sample[0][0]) / 1000000000
        # scale to linear bicolumn
        norm_sample = high - (((high - low) * (maxs - sample)) / rng)
        # padding
        return np.pad(norm_sample, ((
            0, MAX_FLOW_LEN - sample.shape[0]), (0, 0)), 'constant', constant_values=(0, 0))

    global model_path, feature_list

    from tensorflow.keras.models import load_model
    model = load_model(model_path)

    ids_list = []
    data = []
    checkpoint_3 = time.time()
    for k, v in groupby(sorted(packets, key=lambda x: (x.id.saddr, x.id.sport, x.id.daddr, x.id.dport, x.id.proto)),
                        key=lambda x: (x.id.saddr, x.id.sport, x.id.daddr, x.id.dport, x.id.proto)):
        if compute_ids:
            # here session identifiers are formatted, but it is not needed
            ids_list.append((ipv4_to_string(k[0]), port_to_host_int(k[1]), ipv4_to_string(
                k[2]), port_to_host_int(k[3]), protocol_to_string(k[4])))
        data.append(normalize_and_padding_sample(
            np.array([[getattr(x, a) for a in feature_list.keys()] for x in v])))
    data = np.array(data)
    data = np.expand_dims(data, axis=3)
    checkpoint_4 = time.time()
    prediction = model.predict(data, batch_size=2048) > 0.5
    checkpoint_5 = time.time()

    print(f"Execution n°{exec_number}:"
          f"\n\tTIME total: {checkpoint_5 - checkpoint_0}"
          f"\n\tTIME controls: {checkpoint_1 - checkpoint_0}"
          f"\n\tTIME eBPF extraction: {checkpoint_2 - checkpoint_1}"
          f"\n\tTIME spawning process: {checkpoint_3 - checkpoint_2}"
          f"\n\tTIME async (Manipulation + Numpy): {checkpoint_4 - checkpoint_3}"
          f"\n\tTIME prediction: {checkpoint_5 - checkpoint_4}"
          f"\n\tMalicious Sessions: {np.sum(prediction)}"
          f"\n\tTotal Sessions: {data.shape[0]}"
          f"\n\tTotal Packets Extracted: {len(packets)}"
          f"\n\tTotal Packets Padded: {data.shape[0]*data.shape[1] - len(packets)}"
          f"\n\tTotal Packets passed belonging to tracked sessions: {total_pkts_passed_from_sessions}", flush=True)


def extract_sessions(table: TableBase, return_map=False):
    """Function to empty the session map, and return the dictionary
    if specified or the total amount of packets parsed from the eBPF program

    Args:
        table (TableBase): The table of interest
    """
    if is_batch_supp():
        data = table.items_lookup_and_delete_batch()
        if return_map:
            return {(k.saddr, k.sport, k.daddr, k.dport, k.proto): v for k, v in data}
        return sum([v for _, v in data])
    else:
        flows = {} if return_map else 0
        for key, val in table.items():
            if return_map:
                flows[(key.saddr, key.sport, key.daddr,
                       key.dport, key.proto)] = val
            else:
                flows += val
            del table[key]
        return flows


def reaction_function_rest(probe: Plugin) -> Dict[str, any]:
    """Function called via REST interaction
    Args:
        probe (Plugin): The probe of interest
    Returns:
        Dict[str, any]: Dictionary containing times and results of prediction
    """
    global cnt

    checkpoint_0 = time.time()

    exec_number = cnt
    cnt += 1
    if probe._config.ingress:
        probe["ingress"].trigger_read()
    if probe._config.egress:
        probe["egress"].trigger_read()
    task = pool.apply_async(
        extract_sessions, (probe["ingress"]["SESSIONS_TRACKED_DDOS"],))

    checkpoint_1 = time.time()
    packets = list(probe["ingress"]["PACKET_BUFFER_DDOS"].values())
    total_pkts_passed_from_sessions = task.get()
    checkpoint_2 = time.time()

    if packets:
        Process(target=async_prediction, args=(packets, exec_number, checkpoint_0,
                checkpoint_1, checkpoint_2, total_pkts_passed_from_sessions,), daemon=True).start()
        return True
    return False


def reaction_function(probe: Plugin):
    global cnt
    print(f'Execution n° {cnt}: '
          "Got something (asynchronously prediction)" if reaction_function_rest(probe) else "Got nothing!", flush=True)


def pre_compilation(config: ProbeConfig):
    global feature_list, MAX_FLOW_LEN, model_path

    if 'model' not in config.extra:
        raise Exception("No Model has been specified")

    # Storing the model into a temporary file
    model_path = config.extra['model']
    if not os.path.isfile(model_path):
        content = model_path
        model_path = "/tmp/model"
        with open(model_path, "wb+") as fp:
            fp.write(b64decode(content))

    # adjust time_window max value in features
    feature_list['timestamp'][1] = config.time_window

    # set default features active
    if not any([x for x in config.cflags if x in [f"-D{x.upper()}=1" for x in feature_list]]):
        config.cflags += ["-DTIMESTAMP=1", "-DIP_FLAGS=1",
                          "-DTCP_FLAGS=1", "-DTCP_WIN=1", "-DUDP_LEN=1", "-DICMP_TYPE=1"]

    # check if changed N_PACKET_PER_SESSION and adjust parameter
    has_declared_pps = [int(x.split("=")[1])
                        for x in config.cflags if "N_PACKET_PER_SESSION" in x]
    MAX_FLOW_LEN = has_declared_pps[0] if has_declared_pps else 10


def post_compilation(probe: Plugin):
    global feature_list, maxs, rng

    # remove unused features
    active_features = [x for x, _ in probe["ingress"]
                       ["PACKET_BUFFER_DDOS"].Leaf._fields_]
    for key in list(feature_list.keys()):
        if key not in active_features:
            feature_list.pop(key)

    maxs = np.array([x[1] for x in feature_list.values()])
    rng = np.array([x[1] - x[0] for x in feature_list.values()])
