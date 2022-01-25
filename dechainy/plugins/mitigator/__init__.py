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
import ctypes as ct
from dataclasses import dataclass

from typing import List, Union

from ...ebpf import LpmKey
from ...utility import ipv4_to_network_int
from .. import Probe, HookSetting


@dataclass
class MitigatorRule:
    """Class to represent a mitigator rule

    Attributes:
        ip (str): The Ip to block
        netmask (int): The length of the netmask. Default 32.
    """
    netmask: int
    ip: str


@dataclass
class Mitigator(Probe):
    """Mitigator class, an eBPF implementation of an IP/Netmask mitigator."""

    def __post_init__(self):
        self.egress = HookSetting()
        self.ingress.required = True
        super().__post_init__(path=__file__)
        self.__max_rules : int = 1000 if not self.extra or "max_rules" not in self.extra else self.extra["max_rules"]
        self.__rules : List[MitigatorRule] = []
        self.ingress.cflags.append('-DMAX_RULES={}'.format(self.__max_rules))
        
    def get_at(self, rule_id: int) -> MitigatorRule:
        """Function to retrieve a rule at a specific position

        Args:
            rule_id (int): The ID of the rule to be retrieved

        Raises:
            IndexError: The ID is greater than the actual number of rules

        Returns:
            MitigatorRule: The rule retrieved
        """
        if rule_id >= len(self.__rules):
            raise IndexError("The Rule ID provided is wrong")
        return self.__rules[rule_id]

    def get(self) -> str:
        """Function to retrieve all the rules

        Returns:
            List[MitigatorRule]: The array of rules
        """
        return self.__rules

    def delete_at(self, rule_id: int) -> str:
        """Function to delete a rule at a specific position

        Args:
            rule_id (int): The rule ID

        Raises:
            IndexError: The provided ID is greater than the actual number of rules

        Returns:
            int: The ID of the deleted rule
        """
        if rule_id >= len(self.__rules):
            raise IndexError("The Rule ID provided is wrong")

        rule = self.__rules.pop(rule_id)
        key = LpmKey(rule.netmask, ipv4_to_network_int(rule.ip))

        del self._programs.ingress['BLACKLISTED_IPS'][key]
        return rule_id

    def delete(self, rule: MitigatorRule) -> str:
        """Function to delete a rule matching the provided one

        Args:
            rule (MitigatorRule): The Rule to be deleted

        Raises:
            LookupError: The rule is not present

        Returns:
            int: The ID of the deleted rule
        """
        if rule not in self.__rules:
            raise LookupError(
                "Attempting to delete a rule which is not present")
        return self.delete_at(self.__rules.index(rule))

    def insert_at(self, rule_id: int, rule: MitigatorRule) -> str:
        """Function to insert a rule at a specific position

        Args:
            rule_id (int): The ID of the rule
            rule (MitigatorRule): The rule to be inserted

        Raises:
            LookupError: If already exists a similar rule
            IndexError: If the provided ID is greater than the actual number of rules
            MemoryError: If there is no enough room for a new rule

        Returns:
            int: The id of the inserted rule
        """
        if rule in self.__rules:
            raise LookupError(
                "Attempting to insert a rule which is already present")
        if rule_id > len(self.__rules):
            raise IndexError("The Rule ID provided is wrong")
        if rule_id == self.__max_rules:
            raise MemoryError("You reached the maximum amount of rules")

        key = LpmKey(rule.netmask, ipv4_to_network_int(rule.ip))
        self._programs.ingress['BLACKLISTED_IPS'][key] = ct.c_ulong(
            0)
        self.__rules.insert(rule_id, rule)
        return rule_id

    def insert(self, rule: MitigatorRule) -> str:
        """Function to insert a rule without specifying the position (append)

        Args:
            rule (MitigatorRule): The rule to be inserted

        Returns:
            id: The ID of the inserted rule
        """
        return self.insert_at(len(self.__rules), rule)

    def update(self, rule_id: int, rule: MitigatorRule) -> str:
        """Function to update a rule at a specific position

        Args:
            rule_id (int): The ID of the rule to be updated
            rule (MitigatorRule): The new rule to be inserted

        Raises:
            LookupError: There is already a rule like the provided one
            IndexError: The ID is greater than the actual number of rules

        Returns:
            int: The ID of the updated rule
        """
        if rule in self.__rules:
            raise LookupError(
                "Attempting to update a rule which is already present")
        if rule_id >= len(self.__rules):
            raise IndexError("The Rule ID provided is wrong")
        self.delete_at(rule_id)
        self.insert_at(rule_id, rule)
        return rule_id

    def reset(self) -> str:
        """Function to reset all the rules

        Returns:
            int: The number of deleted rules
        """
        ret = len(self.__rules)
        self.__rules.clear()
        self._programs.ingress['BLACKLISTED_IPS'].clear()
        return ret
