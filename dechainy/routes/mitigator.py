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
from ..plugins import Mitigator
from flask import abort, Blueprint, request
from json import loads

__plugin_name = Mitigator.__name__.lower()
__rule_file_name = 'rule'

# getting the reference to the singleton
controller = Controller()

bp = Blueprint(__plugin_name, __name__)


@bp.route(f'/plugins/{__plugin_name}/<probe_name>/reset', methods=['POST'])
def reset_rules(probe_name: str) -> str:
    """Rest endpoint used to reset the rules of a specific Mitigator instance

    Args:
        probe_name (str): The name of the Firewall instance
        program_type (str): The hook of interes (ingress/egress)

    Returns:
        str: The number of rules deleted
    """
    try:
        return controller.execute_cp_function_probe(
            __plugin_name, probe_name, 'reset')
    except exceptions.ProbeNotFoundException as e:
        abort(404, e)
    except exceptions.UnsupportedOperationException as e:
        abort(400, e)


@bp.route(f'/plugins/{__plugin_name}/<probe_name>/rules', methods=['GET', 'POST', 'DELETE'])
def manage_blacklist(probe_name: str) -> Union[List[MitigatorRule], str]:
    """Rest endpoint to get, create or delete a given rule of a specific Mitigator instance

    Args:
        probe_name (str): The name of the Mitigator instance

    Returns:
        Union[List[MitigatorRule], str]: The rules if GET request, else the ID of the deleted/modified one
    """
    try:
        if request.method == 'GET':
            return controller.execute_cp_function_probe(
                __plugin_name, probe_name, 'get')

        if not request.json and not request.files[__rule_file_name]:
            abort(400, 'A rule is needed')

        rule = request.json or loads(request.files[__rule_file_name].read())

        return controller.execute_cp_function_probe(
            __plugin_name, probe_name, 'insert' if request.method == 'POST' else 'delete', MitigatorRule(rule))
    except (exceptions.ProbeNotFoundException, exceptions.UnsupportedOperationException,
            MemoryError, IndexError, LookupError) as e:
        abort(404, e)


@bp.route(f'/plugins/{__plugin_name}/<probe_name>/rules/<int:rule_id>', methods=['GET', 'DELETE', 'PUT', 'POST'])
def manage_rule_at(probe_name: str, rule_id: int) -> Union[MitigatorRule, str]:
    """Rest endpoint to create, modify or delete a rule given its ID, on a specific Mitigator instance

    Args:
        probe_name (str): The name of the Mitigator instance
        id (int): The rule ID

    Returns:
        Union[MitigatorRule, str]: The rule if GET request, else its ID
    """
    try:
        if request.method == 'GET':
            return controller.execute_cp_function_probe(
                __plugin_name, probe_name, 'get_at', rule_id)

        if request.method == 'DELETE':
            return controller.execute_cp_function_probe(
                __plugin_name, probe_name, 'delete_at', rule_id)

        if not request.json and not request.files[__rule_file_name]:
            abort(400, 'A rule is needed')

        rule = request.json or loads(request.files[__rule_file_name].read())

        return controller.execute_cp_function_probe(
            __plugin_name, probe_name, 'insert_at' if request.method == 'POST' else 'update', rule_id, MitigatorRule(rule))

    except (exceptions.ProbeNotFoundException, exceptions.UnsupportedOperationException,
            MemoryError, IndexError, LookupError) as e:
        abort(404, e)
