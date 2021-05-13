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
from typing import Dict, List, Tuple

from dechainy.plugins import Plugin
from dechainy.utility import ipv4_to_string, port_to_host_int, protocol_to_string

# import json


def sumCPUValues(values: List[any], key: Tuple[any]) -> Tuple[any, List[any]]:
    """Function to aggregate all single values of the percpu map entry

    Args:
        values (List[any]): The values of the PERCPU map
        key (Tuple[any]): The key under analysis

    Returns:
        Tuple[any, List[any]]: The aggregate value and the key in human-readable
    """
    features = [0] * 8
    # summing each cpu values
    for value in values:
        features[0] += value.n_packets
        features[1] += value.n_packets_reverse
        features[2] += value.n_bytes * 8
        features[3] += value.n_bytes_reverse * 8
        if value.method != 0:
            features[4] = value.method
        if value.alive_timestamp > features[5]:
            features[5] = value.alive_timestamp
        if value.start_timestamp > features[6]:
            features[6] = value.start_timestamp
        if value.server_ip != 0:
            features[7] = value.server_ip
    # modifying fields according to client-server and parsing Identifiers
    if features[7] == key.saddr:
        features[0], features[1], features[2], features[3] = features[1], features[0], features[3], features[2]
        correct_key = (key.daddr, key.dport, key.saddr, key.sport, key.proto)
    else:
        correct_key = (key.saddr, key.sport, key.daddr, key.dport, key.proto)

    features = features[:6] + [features[5] - features[6]]
    correct_key = (
        ipv4_to_string(correct_key[0]),
        port_to_host_int(correct_key[1]),
        ipv4_to_string(correct_key[2]),
        port_to_host_int(correct_key[3]),
        protocol_to_string(correct_key[4])
    )
    return correct_key, features


def makeDivision(i: float, j: float) -> float:
    """Function to perform division safely, even when 0 is given

    Args:
        i (float): The nominator
        j (float): The denominator

    Returns:
        float: Result of the division, or -1 if not possible
    """
    return i / j if j else -1


def reaction_function_rest(probe: Plugin) -> Dict[str, any]:
    """Function called when performing the REST request

    Args:
        probe (Plugin): The probe under analysis

    Returns:
        Dict[str, any]: The dictionary containing many computed values
    """
    checkpoint_0 = time.time()

    probe["ingress"].trigger_read()
    probe["egress"].trigger_read()

    data = []
    checkpoint_1 = time.time()
    for key, values in probe["ingress"]["SESSIONS_TRACKED_CRYPTO"].items():
        correct_key, features = sumCPUValues(values, key)
        seconds = features[6] / 1000000000      # duration (s)
        data.append({"id": correct_key, "value": [
            features[5],                        # last timestamp
            features[4],                        # server method
            features[0],                        # client packets
            features[1],                        # server packets
            features[2],                        # client bits
            features[3],                        # server bits
            features[6],                        # duration (ns)
            makeDivision(                       # client pkts per sec
                features[0],
                seconds),
            makeDivision(                       # server pkts per sec
                features[1],
                seconds),
            makeDivision(                       # client bits per sec
                features[2],
                seconds),
            makeDivision(                       # server bits per sec
                features[3],
                seconds),
            makeDivision(                       # client bits over pkts
                features[2],
                features[0]),
            makeDivision(                       # server bits over pkts
                features[3],
                features[1]),
            makeDivision(                       # server pkts over client pkts
                features[1],
                features[0]),
            makeDivision(                       # server bits over client bits
                features[3],
                features[2])]})
        del probe["ingress"]["SESSIONS_TRACKED_CRYPTO"][key]
    checkpoint_2 = time.time()

    if not data:
        return None

    return {"flows": data, "total_time": checkpoint_2 - checkpoint_0,
            "controls_time": checkpoint_1 - checkpoint_0,
            "ebpf_time": checkpoint_2 - checkpoint_1}


def reaction_function(probe: Plugin):
    """Function periodically called locally, just to print the REST return

    Args:
        probe (Plugin): The probe under analysis

    """
    ret = reaction_function_rest(probe)
    if ret:
        print(
            'Got something!\n\t'
            f'TIME total: {ret["total_time"]} (s)\n\t'
            f'TIME controls: {ret["controls_time"]}\n\t'
            f'TIME ebpf extraction + parse: {ret["ebpf_time"]} (s)\n\t'
            f'Sessions: {len(ret["flows"])}', flush=True)
        # print(json.dumps(ret["flows"], indent=2))
    else:
        print('Got nothing ...', flush=True)
