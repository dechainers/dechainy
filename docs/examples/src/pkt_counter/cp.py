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
from typing import Dict
from dechainy.plugins import Plugin


def reaction_function_rest(probe: Plugin) -> Dict[str, int]:
    """Function called when performing the REST request

    Args:
        probe (Plugin): The probe under analysis

    Returns:
        Dict[str, int]: The dictionary containing n° of ingress and egress pkts
    """
    return {'ingress': probe["ingress"]['TOTAL_PACKETS'][0].value,
            'egress': probe["egress"]['TOTAL_PACKETS'][0].value}


def reaction_function(probe: Plugin):
    """Function periodically called locally, just to print the REST result

    Args:
        probe (Plugin): The probe under analysis

    """
    print(reaction_function_rest(probe), flush=True)
