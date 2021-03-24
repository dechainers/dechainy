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
from typing import List, Union
from ..configurations import MitigatorRule
from .. import exceptions, Controller
from ..plugins import Adaptmon
from flask import abort, Blueprint, request
from json import loads

__plugin_name = Adaptmon.__name__.lower()

# getting the reference to the singleton
controller = Controller()

bp = Blueprint(__plugin_name, __name__)


@bp.route(f'/plugins/{__plugin_name}/<probe_name>/<program_type>/metrics/<metric_name>', methods=['GET'])
def retrieve_metric(probe_name: str, program_type: str, metric_name: str) -> any:
    """Rest endpoint to retrieve the value of a defined metric

    Args:
        probe_name (str): The name of the Adaptmon instance
        program_type (str): The type of the program (Ingress/Egress)
        metric_name (str): The name of the metric to be retrieved

    Returns:
        any: The value of the metric
    """
    try:
        return controller.execute_cp_function_probe(
            __plugin_name, probe_name, 'retrieve_metric', program_type, metric_name)
    except (exceptions.ProbeNotFoundException, exceptions.UnsupportedOperationException, LookupError) as e:
        abort(404, e)

@bp.route(f'/plugins/{__plugin_name}/<probe_name>/<program_type>/metrics', methods=['GET'])
def retrieve_metrics(probe_name: str, program_type: str) -> any:
    """Rest endpoint to retrieve the value of all metrics

    Args:
        probe_name (str): The name of the Adaptmon instance
        program_type (str): The type of the program (Ingress/Egress)

    Returns:
        any: The value of the metrics
    """
    try:
        return controller.execute_cp_function_probe(
            __plugin_name, probe_name, 'retrieve_metrics', program_type)
    except (exceptions.ProbeNotFoundException, exceptions.UnsupportedOperationException, LookupError) as e:
        abort(404, e)
