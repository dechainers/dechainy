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
import json
from typing import Dict

from dechainy.configurations import MitigatorRule
from dechainy.plugins import Cluster
from dechainy.utility import ipv4_to_string

counter: int = 0


def reaction_function_rest(cluster: Cluster) -> Dict[str, any]:
    """Function called when performing REST request

    Args:
        cluster (Cluster): The Cluster of interest

    Returns:
        Dict[str, any]: Dictionary containing n° pkts ingress, egress
            and rules mitigated
    """
    global counter
    counter += 1

    cnt_ingress = cluster['adaptmon']['pkt_counter']["ingress"]['TOTAL_PACKETS'][0].value
    cnt_egress = cluster['adaptmon']['pkt_counter']["egress"]['TOTAL_PACKETS'][0].value
    rules = {}
    # NB: it is possible to call the probe specific control plane method instead of directly
    #     accessing the map. Thus, pay attention to what you do.
    for key, cnt in cluster['mitigator']['probe']["ingress"]['BLACKLISTED_IPS'].items():
        rules[f"{ipv4_to_string(key.ip)}/{key.netmask_len}"] = cnt.value

    return {
        'pkt_ingress': cnt_ingress,
        'pkt_egress': cnt_egress,
        'mitigator_rules': rules}


def reaction_function(cluster: Cluster):
    """Function periodically called locally to exec the REST function and print results

    Args:
        cluster (Cluster): The cluster of interest
    """
    global counter

    ret = reaction_function_rest(cluster)

    print('------------------------------\n'
          f'Packet Counter: Ingress({ret["pkt_ingress"]}) Egress({ret["pkt_egress"]})\n'
          f'Mitigator: {json.dumps(ret["mitigator_rules"], indent=2)}')

    if ret['pkt_ingress'] > 10 and not ret['mitigator_rules']:
        print('Filling map with rule')
        # NB: it is possible to directly access the eBPF map, but then the rule would not be pushed into
        #     the Python class. Thus, pay attention to what you do.
        cluster["mitigator"]["probe"].insert(
            MitigatorRule({"netmask": 32, "ip": "8.8.8.8"}))
    print('', flush=True)
