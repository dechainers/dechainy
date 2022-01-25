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
from json import loads
from flask import abort, Blueprint, request, current_app, jsonify

from . import FirewallRule
from ... import exceptions
from ...plugins.firewall import Firewall

__plugin_name = Firewall.__name__.lower()

bp = Blueprint(__plugin_name, __name__)


@bp.route(f'/plugins/{__plugin_name}/<probe_name>/<program_type>/reset', methods=['POST'])
def reset_rules(probe_name: str, program_type: str) -> str:
    """Rest endpoint used to reset the rules of a specific Firewall instance's hook

    Args:
        probe_name (str): The name of the Firewall instance
        program_type (str): The hook of interes (ingress/egress)

    Returns:
        str: The number of rules deleted
    """
    try:
        return current_app.config["controller"].get_probe(__plugin_name, probe_name).reset(program_type)
    except (exceptions.ProbeNotFoundException, exceptions.HookDisabledException) as e:
        abort(404, e)
    except exceptions.UnsupportedOperationException as e:
        abort(400, e)


@bp.route(f'/plugins/{__plugin_name}/<probe_name>/<program_type>/rules', methods=['GET', 'POST', 'DELETE'])
def manage_rules(probe_name: str, program_type: str) -> Union[List[FirewallRule], str]:
    """Rest endpoint to get, create or delete a given rule on a specific Firewall instance's hook

    Args:
        probe_name (str): The name of the Firewall instance
        program_type (str): The hook of interes (ingress/egress)

    Returns:
        Union[List[FirewallRule], str]: The rules if GET request, else the ID of the deleted/modified one
    """
    try:
        probe = current_app.config["controller"].get_probe(__plugin_name, probe_name)
        
        if request.method == 'GET':
            return jsonify(probe.get(program_type))

        if not request.json:
            abort(400, 'A rule is needed')

        return jsonify(probe.insert(program_type, FirewallRule(**request.json)) if request.method == 'POST' else probe.delete(program_type, FirewallRule(**request.json)))
    except (exceptions.ProbeNotFoundException, exceptions.UnsupportedOperationException,
            exceptions.HookDisabledException, MemoryError, IndexError, LookupError) as e:
        abort(404, e)


@bp.route(f'/plugins/{__plugin_name}/<probe_name>/<program_type>/rules/<int:id>', methods=['GET', 'DELETE', 'PUT', 'POST'])
def manage_rule_at(probe_name: str, program_type: str, id: int) -> Union[FirewallRule, str]:
    """Rest endpoint to create, modify or delete a rule given its ID, on a specific Firewall instance's hook

    Args:
        probe_name (str): The name of the Firewall instance
        program_type (str): The hook of interes (ingress/egress)
        id (int): The rule ID

    Returns:
        Union[FirewallRule, str]: The rule if GET request, else its ID
    """
    try:
        probe = current_app.config["controller"].get_probe(__plugin_name, probe_name)
        
        if request.method == 'GET':
            return jsonify(probe.get_at(program_type, id))

        if request.method == 'DELETE':
            return jsonify(probe.delete_at(program_type, id))

        if not request.json:
            abort(400, 'A rule is needed')

        return jsonify(probe.insert_at(program_type, id, FirewallRule(**request.json)) if request.method == 'POST' else probe.update(program_type, id, FirewallRule(**request.json)))

    except (exceptions.ProbeNotFoundException, exceptions.UnsupportedOperationException,
            exceptions.HookDisabledException, MemoryError, IndexError, LookupError) as e:
        abort(404, e)
