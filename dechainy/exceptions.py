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


class PluginNotFoundException(Exception):
    """
    Exception to be thrown when the desired Plugin has not been found
    """
    pass


class ProbeNotFoundException(Exception):
    """
    Exception to be thrown when the desired Probe has not been found
    """
    pass


class UnsupportedOperationException(Exception):
    """
    Exception to be thrown when requiring an endpoint (e.g., "/exec") not supported by the probe/cluster
    """
    pass


class ProbeAlreadyExistsException(Exception):
    """
    Exception to be thrown when the desired Probe already exists in the system
    """
    pass


class ClusterNotFoundException(Exception):
    """
    Exception to be thrown when the desired Cluster has not been found
    """
    pass


class ProbeInClusterException(Exception):
    """
    Exception to be thrown when the desired plugin to delete is in a Cluster
    """
    pass


class UnknownInterfaceException(Exception):
    """
    Exception to be thrown when the desired Interface does not exist
    """
    pass


class MissingInterfaceInProbeException(Exception):
    """
    Exception to be thrown when the Interface is not specified in the Probe Configuration
    """
    pass


class HookDisabledException(Exception):
    """
    Exception to be thrown when performing operations on a hook that has been disabled in the probe config
    """
    pass


class NoCodeProbeException(Exception):
    """
    Exception to be thrown when creating a probe without at least 1 program type active
    """
    pass
