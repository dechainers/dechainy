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
from importlib import import_module
from importlib.util import find_spec
from typing import Tuple, List
from logging import INFO, NOTSET, getLogger
import sys

from .controller import Controller


def create_server(log_level=INFO, plugins_to_load: List[str] = []) -> Tuple[any, Controller]:
    from flask import Flask
    """Function to return a Flask Server and a Controller given the parameters.
    It is allowed to have multiple servers, but they must share the same Controller
    instance, otherwise there could be problems with the network interfaces cards.

    Args:
        log_level ([type], optional): log level info integer. Defaults to INFO.
        plugins_to_load (List[str], optional): list of plugins to load. If None, then load all of them. Defaults to None.

    Returns:
        Tuple[Flask, Controller]: [description]
    """
    ctr = Controller(log_level=log_level, plugins_to_load=plugins_to_load)
    # dynamically import default routes
    from .rest import bp
    app = Flask(__name__)
    if log_level is not None:
        if log_level == NOTSET:
            cli = sys.modules['flask.cli']
            cli.show_server_banner = lambda *x: None
            app.logger.disabled = True
            getLogger('werkzeug').disabled = True
        else:
            app.logger.setLevel(log_level)
            getLogger('werkzeug').setLevel(log_level)
    app.register_blueprint(bp)
    for plugin in ctr.get_plugin():
        target = '{}.plugins.{}.routes'.format(__name__, plugin)
        # dynamically load per-plugin routes if any
        if find_spec(target):       
            module = import_module(target)
            app.register_blueprint(module.bp)
    app.config['controller'] = ctr
    return app, ctr
