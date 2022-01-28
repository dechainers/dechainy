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
import os
import importlib

from types import ModuleType
from typing import List, Union
from flask import request, abort, Blueprint, current_app, jsonify

from . import exceptions
from .plugins import Probe, Cluster


bp = Blueprint('main', __name__)


@bp.route('/clusters', methods=['GET', 'POST'])
@bp.route('/clusters/<cluster_name>', methods=['GET', 'DELETE'])
def manage_clusters(cluster_name: str = None) -> Cluster:
    """Rest endpoint to get, create or modify a Cluster instance

    Args:
        cluster_name (str): The name of the Cluster instance

    Returns:
        Union[ClusterConfig, str]: The Cluster if GET, else its name
    """
    try:
        if request.method == 'DELETE':
            current_app.config['controller'].delete_cluster(cluster_name)
            return cluster_name

        if request.method == 'POST':
            if not request.json:
                abort(400, 'A configuration is needed')

            config = request.json
            current_app.config['controller'].create_cluster(Cluster(**config))
        return jsonify(current_app.config['controller'].get_cluster(cluster_name))
    except (exceptions.ClusterNotFoundException, exceptions.NoCodeProbeException) as e:
        abort(404, e)
    except (exceptions.CustomCPDisabledException, exceptions.ClusterWithoutCPException) as e:
        abort(400, e)


@bp.route('/plugins/<plugin_name>', methods=['GET', 'POST'])
@bp.route('/plugins/<plugin_name>/<probe_name>', methods=['GET', 'DELETE'])
def manage_probe(plugin_name: str, probe_name: str = None) -> Probe:
    """Rest endpoint to get, create or modify an instance of a given Plugin

    Args:
        plugin_name (str): The name of the Plugin
        probe_name (str): The name of the instance

    Returns:
        Union[ProbeConfig, str]: The instance if GET, else its name
    """
    try:
        if request.method == 'DELETE':
            current_app.config['controller'].delete_probe(plugin_name, probe_name)
            return "{}_{}".format(plugin_name, probe_name)
        if request.method == 'POST':
            if not request.json:
                abort(400, 'A configuration is needed')

            probe = getattr(current_app.config['controller'].get_plugin(plugin_name), plugin_name.capitalize())(**request.json)
            current_app.config['controller'].create_probe(probe)
        return jsonify(current_app.config['controller'].get_probe(plugin_name, probe_name))
    except (exceptions.PluginNotFoundException, exceptions.ProbeNotFoundException, exceptions.ProbeAlreadyExistsException) as e:
        abort(404, e)
    except exceptions.ProbeInClusterException as e:
        abort(400, e)


@bp.route(f'/plugins/<plugin_name>/<probe_name>/<program_type>/metrics', methods=['GET'])
@bp.route(f'/plugins/<plugin_name>/<probe_name>/<program_type>/metrics/<metric_name>', methods=['GET'])
def retrieve_metric(plugin_name: str, probe_name: str, program_type: str, metric_name: str = None) -> any:
    """Rest endpoint to retrieve the value of a defined metric

    Args:
        plugin_name (str): The name of the plugin
        probe_name (str): The name of the Adaptmon instance
        program_type (str): The type of the program (Ingress/Egress)
        metric_name (str): The name of the metric to be retrieved

    Returns:
        any: The value of the metric
    """
    try:
        return current_app.config['controller'].get_probe(plugin_name, probe_name).retrieve_metric(program_type, metric_name)
    except (exceptions.ProbeNotFoundException, exceptions.UnsupportedOperationException, LookupError) as e:
        abort(404, e)


@bp.route('/plugins', methods=['GET', 'POST'])
@bp.route('/plugins/<plugin_name>', methods=['DELETE'])
def manage_plugin(plugin_name: str = None) -> Union[ModuleType, List[ModuleType]]:
    """Rest endpoint to get, create or modify an instance of a given Plugin

    Args:
        plugin_name (str): The name of the Plugin
        probe_name (str): The name of the instance

    Returns:
        Union[ProbeConfig, str]: The instance if GET, else its name
    """
    try:
        print(plugin_name)
        if request.method == 'DELETE':
            current_app.config['controller'].delete_plugin(plugin_name)
            return plugin_name
        elif request.method == 'POST':
            if not request.form["name"]:
                abort(400, 'A name for the plugin is needed')
            plugin_name = request.form["name"]
            if not request.files["module"]:
                abort(400, 'A Module is needed')

            target = os.path.join(os.path.dirname(__file__), "plugins", plugin_name)
            if os.path.isdir(target):
                abort(404, 'A plugin with this name already exists')

            os.makedirs(target)
            request.files["module"].save(os.path.join(target, "__init__.py"))

            for file in ["ingress", "egress", "ebpf"]:
                if not request.files[file]:
                    continue
                request.files[file].save(os.path.join(target, "{}.c".format(file)))
            
            current_app.config['controller'].create_plugin(plugin_name, "{}.plugins.{}".format(__package__, plugin_name))
        ret = current_app.config['controller'].get_plugin(plugin_name)
        return plugin_name if plugin_name else jsonify(list(ret.keys()))
    except (exceptions.PluginNotFoundException, exceptions.ProbeNotFoundException, exceptions.ProbeAlreadyExistsException, exceptions.NoCodeProbeException) as e:
        abort(404, e)


@bp.route('/')
def index() -> str:
    """Rest endpoint to test whether the server is correctly working

    Returns:
        str: The default message string
    """
    return 'DeChainy server greets you :D'
