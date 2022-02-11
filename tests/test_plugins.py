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
class TestPlugin(unittest.TestCase):

    @classmethod
    def tearDownClass(cls):
        controller.delete_plugin()

    def test1_delete_plugins(self):
        controller.delete_plugin()

    def test2_create_plugin_invalid1(self):
        with self.assertRaises(exceptions.InvalidPluginException):
            controller.create_plugin(os.path.join(
                os.path.dirname(__file__), "dumb_plugins", "invalid1"))

    def test3_create_plugin_invalid2(self):
        with self.assertRaises(exceptions.InvalidPluginException):
            controller.create_plugin(os.path.join(
                os.path.dirname(__file__), "dumb_plugins", "invalid2"))

    def test4_create_plugin_valid(self):
        controller.create_plugin(os.path.join(
            os.path.dirname(__file__), "dumb_plugins", "valid"))

    def test5_plugin_not_found(self):
        with self.assertRaises(exceptions.PluginNotFoundException):
            controller.get_plugin('plugin0')

    def test6_plugin_found(self):
        assert controller.get_plugin('valid')

    def test7_plugin_already_exists(self):
        with self.assertRaises(exceptions.PluginAlreadyExistsException):
            controller.create_plugin(os.path.join(
                os.path.dirname(__file__), "dumb_plugins", "valid"))

    def test8_plugin_updated(self):
        controller.create_plugin(os.path.join(
            os.path.dirname(__file__), "dumb_plugins", "valid"), update=True)

    def test9_delete_plugin_valid(self):
        controller.delete_plugin('valid')

    def test10_delete_plugin_invalid(self):
        with self.assertRaises(exceptions.PluginNotFoundException):
            controller.delete_plugin('invalid1')


if __name__ == '__main__':
    unittest.main()
