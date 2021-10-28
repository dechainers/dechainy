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
from os import getcwd
from os.path import isfile
from json import load
from signal import SIGINT, SIGTERM, signal, pause

from .configurations import AppConfig, ServerConfig
from . import Controller, create_server

# The path to check for the startup file is <current>/startup.json
__startup_file = f'{getcwd()}/startup.json'


def __spawn_server(config: AppConfig):
    """Function to create an instance of DeChainy with also the server instance.

    Args:
        config (AppConfig): the startup configuration detetched
    """
    app, controller = create_server(
        log_level=config.log_level, plugins_to_load=config.plugins, custom_cp=config.custom_cp)
    for cluster in config.clusters:
        controller.create_cluster(cluster.name, cluster)
    for probe in config.probes:
        controller.create_probe(probe.plugin_name, probe.name, probe)
    # NB: the live debug mode gives problems, avoid it
    app.run(
        debug=False,
        host=config.server.address,
        port=config.server.port,
        use_reloader=False)


def __spawn_local(config: AppConfig):
    """Function to create an instance of DeChainy without the server instance.

    Args:
        config (AppConfig): the startup configuration
    """
    # As there is no server, if no probes specified then exit immediately
    if not config.clusters and not config.probes:
        print(
            'No probes or clusters specified, starting DeChainy locally wouldn\'t make sense')
        exit(1)
    controller = Controller(log_level=config.log_level,
                            plugins_to_load=config.plugins, custom_cp=config.custom_cp)
    for cluster in config.clusters:
        controller.create_cluster(cluster.name, cluster)
    for probe in config.probes:
        controller.create_probe(probe.plugin_name, probe.name, probe)
    signal(SIGINT, lambda x, y: None)
    signal(SIGTERM, lambda x, y: None)
    pause()


def main():
    """Function used when the module is called as main file. It provides, given the provided (or not)
    startup file, a running Controller and optionally a REST server
    """
    config: AppConfig = AppConfig()

    if not isfile(__startup_file):
        config.server = ServerConfig()
        __spawn_server(config=config)
    else:
        with open(__startup_file) as fp:
            config = AppConfig(load(fp))
        __spawn_server(
            config=config) if config.server else __spawn_local(config)


if __name__ == '__main__':
    main()
