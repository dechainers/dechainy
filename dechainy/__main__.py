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
import argparse

from . import create_server


def _parse_arguments():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-a', '--address', help='server address', type=str, default='0.0.0.0')
    parser.add_argument('-p', '--port', help='server port', type=int, default=8080)
    parser.add_argument('-l', '--load', help='comma-separated list of plugins to load (empty=all)', type=str, default="")
    parser.add_argument('-d', '--debug', help='server debug mode', action="store_true")
    return parser.parse_args.__dict__


def main():
    """Function used when the module is called as main file. It provides, given the provided (or not)
    startup file, a running Controller and optionally a REST server
    """
    args = _parse_arguments()
    app, _ = create_server(args["log_level"], args["plugins_to_load"].split(","))
    app.run(host=args["address"], port=args["port"], debug=args["debug"], use_reloader=False)
    

if __name__ == '__main__':
    main()
