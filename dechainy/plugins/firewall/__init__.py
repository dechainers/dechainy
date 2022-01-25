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

from math import ceil
from typing import Dict, List

from ...ebpf import BPF, LpmKey
from ...utility import protocol_to_int, ipv4_to_network_int, port_to_network_int
from ...exceptions import HookDisabledException
from .. import Probe


@dataclass
class FirewallRule:
    """Class to represent a firewall iptable-like rule

    Attributes:
        src (str): The source address to match. Default None.
        dst (str): The destination address to match. Default None.
        sport (int): The source port to match. Default None.
        dport (int): The destination port to match. Default None.
        l4proto (str): The Layer 4 protocol to match. Default None.
        tcpflags (str): A string containing the names of the TCP Flags to match. Default None.
    """

    src: str = None
    dst: str = None
    sport: int = None
    dport: int = None
    l4proto: str = None
    tcpflags: str = None
    
    def __post_init__(self):
        if not self.src and not self.dst and not self.sport and not self.dport and not self.l4proto and not self.tcpflags:
            raise KeyError("Impossible inserting a rule without specifying at least a field")


@dataclass
class Firewall(Probe):
    """Firewall class, an eBPF implementation of an iptables-like one."""

    # Size of the eBPF maps, how many entries can they accept
    _MAPS = ['IPV4_SRC', 'IPV4_DST', 'PORT_SRC',
             'PORT_DST', 'IP_PROTO', 'TCP_FLAGS']
    _ALL_MAPS = _MAPS + [f"{x}_WILDCARDS" for x in _MAPS]

    def __post_init__(self):
        self.rule_ids_max_entry: int = 10000 if "rule_ids_max_entry" not in self.extra else self.extra["rule_ids_max_entry"]
        self.max_rules: int = 1000 if "max_rules" not in self.extra else self.extra["max_rules"]
        self.rule_ids_word_per_entry : int = ceil(self.max_rules / 64)
        # Each entry hosts 64 rules
        self.rule_ids_word_per_entry = ceil(self.max_rules / 64)
        cflags = ['-DFW_ACTION_DEFAULT=DROP',
            f'-DRULE_IDS_MAX_ENTRY={self.rule_ids_max_entry}',
            f'-DMAX_RULES={self.max_rules}',
            f'-DRULE_IDS_WORDS_PER_ENTRY={self.rule_ids_word_per_entry}']
        self.__rules : Dict[str, List[FirewallRule]] = {}
        if not self.egress.required:
            self.ingress.required = True
        for hook in ["ingress", "egress"]:
            conf = getattr(self, hook)
            if conf.required:
                conf.cflags = cflags
                conf.code = None
                self.__rules[hook] = []
        super().__post_init__(path=__file__)

    def __check_hook_active(self, program_type):
        if program_type not in self.__rules:
            raise HookDisabledException(
                f"The hook {program_type} is not active for this probe")
            
    def get_at(self, program_type: str, rule_id: int) -> FirewallRule:
        """Function to retrieve a rule at a specific position

        Args:
            program_type (str): The hook of interest (ingress/egress)
            rule_id (int): The ID of the rule

        Raises:
            IndexError: The provided ID is greater than the actual number of rules

        Returns:
            FirewallRule: The retrieved rule
        """
        self.__check_hook_active(program_type)
        if rule_id >= len(self.__rules[program_type]):
            raise IndexError("The Rule ID provided is wrong")
        return self.__rules[program_type][rule_id]

    def get(self, program_type: str) -> str:
        """Function to retrieve all the rules for a specific hook

        Args:
            program_type (str): The hook of interest (ingress/egress)

        Returns:
            List[FirewallRule]: The list of rules
        """
        self.__check_hook_active(program_type)
        return self.__rules[program_type]

    def delete_at(self, program_type: str, rule_id: int) -> str:
        """Function to delete a rule at a given position (ID)

        Args:
            program_type (str): The hook of interest (ingress/egress)
            rule_id (int): The ID of the rule to be deleted

        Raises:
            IndexError: The provided ID is greater than the number of actual rules

        Returns:
            int: The rule ID
        """
        self.__check_hook_active(program_type)
        if rule_id >= len(self.__rules[program_type]):
            raise IndexError("The Rule ID provided is wrong")
        self.__rules[program_type].pop(rule_id)
        word, offset_ok = (rule_id // 64, 64 - rule_id % 64)
        prog = getattr(self._programs, program_type)
        
        # Foreach map, also for the WILDCARDS ones, iterate through every
        # key-value and shift left the rules by 1, to remove the target one
        for map_name in Firewall._ALL_MAPS:
            for key, value in prog[map_name].items():
                arr = value.rule_words
                cnt_zeros = 0
                carry = 0
                # Starting from right to left
                for w in range(self.rule_ids_word_per_entry - 1, word, -1):
                    cnt_zeros += int(arr[w] == 0)
                    tmp = carry
                    carry = arr[w] >> 63
                    arr[w] = (arr[w] << 1) | tmp
                cnt_zeros += int(arr[word] == 0)
                # If all zeros, then remove the entire entry
                if cnt_zeros == self.rule_ids_word_per_entry:
                    del prog[map_name][key]
                    continue
                # Finishing the current word, which has also the offset into account
                ok = (arr[word] >> offset_ok) << offset_ok
                to_shift = (arr[word] & (pow(2, offset_ok) - 1)) << 1 | carry
                arr[word] = ok | to_shift
                prog[map_name][key] = arr
        prog['ACTIONS'][ct.c_uint32(
            rule_id)] = ct.c_uint8(BPF.TC_ACT_OK if self.mode == BPF.SCHED_CLS else BPF.XDP_PASS)
        return rule_id

    def delete(self, program_type: str, rule: FirewallRule) -> str:
        """Function to delete a rule matching the provided one

        Args:
            program_type (str): The hook of interest (ingress/egress)
            rule (FirewallRule): The rule to be deleted

        Raises:
            LookupError: If the rule does not match any of the present ones

        Returns:
            int: The ID of the deleted rule
        """
        self.__check_hook_active(program_type)
        if rule not in self.__rules[program_type]:
            raise LookupError(
                "Attempting to delete a rule which is not present")
        return self.delete_at(program_type, self.__rules[program_type].index(rule))

    def insert_at(self, program_type: str, rule_id: int, rule: FirewallRule) -> str:
        """Function to insert a rule at a given position. All the following ones are shifted

        Args:
            program_type (str): The hook of interest (ingress/egress)
            rule_id (int): The ID of the rule (position)
            rule (FirewallRule): The rule to be inserted

        Raises:
            LookupError: The new rule is already present
            IndexError: The rule ID is greater than the actual number of rules
            MemoryError: There is no room for more rules

        Returns:
            int: The ID of the rule
        """
        self.__check_hook_active(program_type)
        if rule in self.__rules[program_type]:
            raise LookupError(
                "Attempting to insert a rule which is already present")
        if rule_id > len(self.__rules[program_type]):
            raise IndexError("The Rule ID provided is wrong")
        if rule_id == self.max_rules:
            raise MemoryError("You reached the maximum amount of rules")

        word, offset = (rule_id // 64, 63 - rule_id % 64)
        offset_ok = offset + 1

        prog = getattr(self._programs, program_type)
        # If the id is in the middle of the list, then all the following rules has
        # to be shifted right by 1, for each map (also WILDCARDS)
        if rule_id < len(self.__rules[program_type]):
            for map_name in Firewall._ALL_MAPS:
                for key, value in prog[map_name].items():
                    # Starting from left to right, thus the 1st word has also the offset
                    # into account
                    arr = value.rule_words
                    carry = arr[word] & 1
                    ok = (arr[word] >> offset_ok) << offset_ok
                    to_shift = (arr[word] & (pow(2, offset_ok) - 1)) >> 1
                    arr[word] = ok | to_shift
                    # Finishing all the other words
                    for w in range(word + 1, self.__rule_ids_word_per_entry):
                        tmp = carry
                        carry = arr[w] & 1
                        arr[w] = (arr[w] >> 1) | (tmp << 63)
                    prog[map_name][key] = arr

        # Insert into the maps, at the specific position the value 1, according
        # to the values specified in the rule
        for map_name, value in zip(Firewall._MAPS, Firewall.translate_rule(rule)):
            if value is None:
                map_name = f'{map_name}_WILDCARDS'
                value = 0
            if value in prog[map_name]:
                arr = prog[map_name][value].rule_words
            else:
                arr = (ct.c_uint64 * self.rule_ids_word_per_entry)()
            arr[word] |= (1 << offset)
            prog[map_name][value] = arr
        prog['ACTIONS'][ct.c_uint32(
            rule_id)] = ct.c_uint8(BPF.TC_ACT_SHOT if self.mode == BPF.SCHED_CLS else BPF.XDP_DROP)
        self.__rules[program_type].insert(rule_id, rule)
        return rule_id

    def insert(self, program_type: str, rule: FirewallRule) -> str:
        """Function to insert the rule given no position (append)

        Args:
            program_type (str): The hook of interest (ingress/egress)
            rule (FirewallRule): The rule to be inserted

        Returns:
            int: The rule ID
        """
        return self.insert_at(program_type, len(self.__rules[program_type]), rule)

    def update(self, program_type: str, rule_id: int, rule: FirewallRule) -> str:
        """Function to update a specific rule given its ID

        Args:
            program_type (str): The hook of interest (ingress/egress)
            rule_id (int): The ID of the rule to be updated
            rule (FirewallRule): The new rule to be inserted

        Raises:
            LookupError: The new rule is already present
            IndexError: The rule ID is greater than the actual number of rules

        Returns:
            int: The id of the rule
        """
        self.__check_hook_active(program_type)
        if rule in self.__rules[program_type]:
            raise LookupError(
                "Attempting to update a rule which is already present")
        if rule_id >= len(self.__rules[program_type]):
            raise IndexError("The Rule ID provided is wrong")
        self.delete_at(program_type, rule_id)
        self.insert_at(program_type, rule_id, rule)
        return rule_id

    def reset(self, program_type: str) -> str:
        """Function to reset the rules of the Firewall instance

        Args:
            program_type (str): The hook of interest (ingress/egress)

        Returns:
            int: The number of rules erased
        """
        self.__check_hook_active(program_type)
        ret = len(self.__rules[program_type])
        self.__rules[program_type].clear()
        for map_name in Firewall._ALL_MAPS:
            getattr(self._programs, program_type)[map_name].clear()
        return ret

    @staticmethod
    def translate_rule(rule: FirewallRule) -> List[any]:
        """Static function to translate a rule into values ready to be inserted in the eBPF maps.

        Args:
            rule (FirewallRule): The rule to be converted

        Returns:
            List[any]: List of converted fields using ctypes
        """
        def translate_ip(ip: str):
            tmp = ip.split("/")
            return LpmKey(ct.c_uint32(int(tmp[1]) if len(tmp) == 2 else 32), ct.c_uint32(ipv4_to_network_int(tmp[0])))

        def translate_flags(flags: str):
            upper = flags.upper()
            ret = 0
            for i, f in enumerate(["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"]):
                if f in upper:
                    ret |= (1 << i)
            return ct.c_uint8(ret)

        return [
            translate_ip(rule.src) if rule.src else None,
            translate_ip(rule.dst) if rule.dst else None,
            ct.c_uint16(port_to_network_int(rule.sport)
                        ) if rule.sport else None,
            ct.c_uint16(port_to_network_int(rule.dport)
                        ) if rule.dport else None,
            ct.c_uint8(protocol_to_int(rule.l4proto)
                       ) if rule.l4proto else None,
            translate_flags(rule.tcpflags) if rule.tcpflags else None
        ]
