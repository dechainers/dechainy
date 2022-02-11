# Copyright 2022 DeChainers
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
import unittest
import os

from dechainy.controller import Controller
import dechainy.exceptions as exceptions

controller = Controller()


@unittest.skipIf(os.getuid(), reason='Root for BCC')
class TestProbes(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        controller.create_plugin(os.path.join(
            os.path.dirname(__file__), "dumb_plugins", "valid"))

    @classmethod
    def tearDownClass(cls):
        controller.delete_plugin()

    def test1_get_probe_invalid(self):
        with self.assertRaises(exceptions.ProbeNotFoundException):
            controller.get_probe('valid', 'attempt')

    def test2_create_probe(self):
        probe = controller.get_plugin('valid').Valid(
            name="attempt", interface="lo")
        controller.create_probe(probe)

    def test3_get_probe_valid(self):
        controller.get_probe('valid', 'attempt')

    def test4_remove_probe_invalid1(self):
        with self.assertRaises(exceptions.ProbeNotFoundException):
            controller.delete_probe('valid', 'aaaaaa')

    def test5_remove_probe_invalid2(self):
        with self.assertRaises(exceptions.PluginNotFoundException):
            controller.delete_probe('aaaaaa', 'attempt')

    def test6_remove_probe_valid(self):
        controller.delete_probe('valid', 'attempt')


if __name__ == '__main__':
    unittest.main()
