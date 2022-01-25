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
from ... import exceptions
from . import Mitigator, MitigatorRule
from flask import abort, Blueprint, request, jsonify, current_app

from . import MitigatorRule


__plugin_name = Mitigator.__name__.lower()

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
        return jsonify(current_app.config["controller"].get_probe(__plugin_name, probe_name).reset())
    except exceptions.ProbeNotFoundException as e:
        abort(404, e)
    except exceptions.UnsupportedOperationException as e:
        abort(400, e)


@bp.route(f'/plugins/{__plugin_name}/<probe_name>/rules', methods=['GET', 'POST', 'DELETE'])
def manage_rules(probe_name: str) -> Union[List[MitigatorRule], str]:
    """Rest endpoint to get, create or delete a given rule of a specific Mitigator instance

    Args:
        probe_name (str): The name of the Mitigator instance

    Returns:
        Union[List[MitigatorRule], str]: The rules if GET request, else the ID of the deleted/modified one
    """
    try:
        probe = current_app.config["controller"].get_probe(__plugin_name, probe_name)
        if request.method == 'GET':
            return jsonify(probe.get())

        if not request.json:
            abort(400, 'A rule is needed')
            
        rule = MitigatorRule(**request.json)
        
        return jsonify(probe.insert(rule) if request.method == 'POST' else probe.delete(rule))
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
        probe = current_app.config["controller"].get_probe(__plugin_name, probe_name)
        
        if request.method == 'GET':    
            return jsonify(probe.get_at(rule_id))

        if request.method == 'DELETE':
            return jsonify(probe.delete_at(rule_id))

        if not request.json:
            abort(400, 'A rule is needed')

        rule = MitigatorRule(**request.json)
        return jsonify(probe.insert_at(rule_id, rule) if request.method == 'POST' else probe.update(rule_id, MitigatorRule(rule)))
    except (exceptions.ProbeNotFoundException, exceptions.UnsupportedOperationException,
            MemoryError, IndexError, LookupError) as e:
        abort(404, e)
