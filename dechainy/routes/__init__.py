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
from typing import Union
from flask import request, abort, Blueprint
from json import loads
from .. import Controller, exceptions
from ..configurations import ClusterConfig, ProbeConfig

# getting the reference to the singleton
controller = Controller()

# configuration file name pushed when creating probes/clusters
__config_file_name = 'config'

bp = Blueprint('main', __name__)


@bp.route('/clusters/<cluster_name>', methods=['GET', 'POST', 'DELETE'])
def manage_clusters(cluster_name: str) -> Union[ClusterConfig, str]:
    """Rest endpoint to get, create or modify a Cluster instance

    Args:
        cluster_name (str): The name of the Cluster instance

    Returns:
        Union[ClusterConfig, str]: The Cluster if GET, else its name
    """
    try:
        if request.method == 'DELETE':
            return controller.delete_cluster(cluster_name)

        if request.method == 'GET':
            return controller.get_cluster(cluster_name).__repr__()

        if not request.json and not request.files[__config_file_name]:
            abort(400, 'A configuration is needed')

        config = request.json or loads(
            request.files[__config_file_name].read())
        return controller.create_cluster(cluster_name, ClusterConfig(config))
    except (exceptions.ClusterNotFoundException, exceptions.NoCodeProbeException) as e:
        abort(404, e)


@bp.route('/clusters/<cluster_name>/exec')
def exec_cluster_custom_cp(cluster_name: str) -> any:
    """Rest endpoint to exec the previously specified function of a Cluster instance

    Args:
        cluster_name (str): The name of the Cluster

    Returns:
        any: The value specified in the user-defined function
    """
    try:
        return controller.execute_cp_function_cluster(cluster_name, 'exec')
    except exceptions.ClusterNotFoundException as e:
        abort(404, e)
    except exceptions.UnsupportedOperationException as e:
        abort(400, e)


@bp.route('/plugins/<plugin_name>/<probe_name>', methods=['GET', 'POST', 'DELETE'])
def manage_probe(plugin_name: str, probe_name: str) -> Union[ProbeConfig, str]:
    """Rest endpoint to get, create or modify an instance of a given Plugin

    Args:
        plugin_name (str): The name of the Plugin
        probe_name (str): The name of the instance

    Returns:
        Union[ProbeConfig, str]: The instance if GET, else its name
    """
    if request.method == 'DELETE':
        try:
            return controller.delete_probe(plugin_name, probe_name)
        except (exceptions.PluginNotFoundException, exceptions.ProbeNotFoundException) as e:
            abort(404, e)
        except exceptions.ProbeInClusterException as e:
            abort(400, e)

    if request.method == 'GET':
        try:
            return controller.get_probe(plugin_name, probe_name)
        except (exceptions.PluginNotFoundException, exceptions.ProbeNotFoundException) as e:
            abort(404, e)

    if not request.json and not request.files[__config_file_name]:
        abort(400, 'A configuration is needed')

    config = request.json or loads(request.files[__config_file_name].read())
    try:
        return controller.create_probe(plugin_name, probe_name, ProbeConfig(config))
    except (exceptions.PluginNotFoundException, exceptions.ProbeAlreadyExistsException, exceptions.NoCodeProbeException) as e:
        abort(404, e)


@bp.route('/plugins/<plugin_name>/<probe_name>/exec')
def exec_probe_custom_cp(plugin_name: str, probe_name: str) -> any:
    """Rest endpoint to exec the function previosly specified on a specific Plugin instance

    Args:
        plugin_name (str): The name of the plugin
        probe_name (str): The name of the instance

    Returns:
        any: The return value specified in the user-defined function
    """
    try:
        return controller.execute_cp_function_probe(
            plugin_name, probe_name, 'exec')
    except (exceptions.PluginNotFoundException, exceptions.ProbeNotFoundException) as e:
        abort(404, e)
    except exceptions.UnsupportedOperationException as e:
        abort(400, e)


@bp.route('/')
def index() -> str:
    """Rest endpoint to test whether the server is correctly working

    Returns:
        str: The default message string
    """
    return 'DeChainy server greets you :D'
