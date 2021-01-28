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
from argparse import ArgumentParser
from json import dumps

import base64
import subprocess


def main():
    args = parseArguments()
    path = args['path_to_file']
    # try to guess file type
    file_type = subprocess.run(['file', '-b', '--mime-type', path], capture_output=True).stdout.decode('utf-8')
    # if binary (e.g., machine learning model in .h5 format), then open it in "rb" mode and base64-encode it
    mode = 'r' if any(x in file_type for x in ['x-python', 'x-c']) or ".py" in path or ".c" in path else 'rb'
    with open(path, mode) as fp:
        content = dumps(fp.read()) if mode == 'r' else base64.b64encode(fp.read())
    print(content)


def parseArguments():
    parser = ArgumentParser()
    parser.add_argument('path_to_file', help='path to the file to be escaped', type=str)
    return parser.parse_args().__dict__


if __name__ == '__main__':
    main()
