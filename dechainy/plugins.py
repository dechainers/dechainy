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
from math import ceil
from types import ModuleType
from typing import List, Union
from json import dumps
import ctypes as ct

from .exceptions import HookDisabledException
from .configurations import ClusterCompilation, ClusterConfig, FirewallRule, MitigatorRule, ProbeCompilation, ProbeConfig
from .ebpf import BPF, LpmKey, Program
from .utility import Dict, CPThread, protocol_to_int, ipv4_to_network_int, port_to_network_int


class BaseEntity:
    """Base class to define an entity (Plugin or Cluster) with many properties in common.

    Args:
        config (Union[ProbeConfig, ClusterConfig]): The configuration of the object
        module (ModuleType): The module containing additional functions
        programs (Union[ProbeCompilation, ClusterCompilation]): The compiled eBPF programs for the Probe or Cluster

    Attributes:
        is_destroyed (bool): True while the instance is not destroyed
        thread (CPThread): The locally created thread if needed
        module (ModuleType): The module containing additional functions
        config (Union[ProbeConfig, ClusterConfig]): The configuration of the object
        programs (Union[ProbeCompilation, ClusterCompilation]): The compiled eBPF programs for the Probe or Cluster
    """

    def __init__(self, config: Union[ProbeConfig, ClusterConfig], module: ModuleType,
                 programs: Union[ProbeCompilation, ClusterCompilation]):
        self._is_destroyed: bool = False
        self._thread: CPThread = None
        self._module: ModuleType = module
        self._config: Union[ProbeConfig, ClusterConfig] = config
        self.programs: Union[ProbeCompilation, ClusterCompilation] = programs
        # If the module has a post_compilation function, call it
        if hasattr(module, "post_compilation"):
            module.post_compilation(self)
        # If required, run local thread to execute non-REST function
        if hasattr(module, "reaction_function"):
            self._thread = CPThread(
                target=module.reaction_function, args=(self,), time_window=self._config.time_window)
            self._thread.start()

    def __del__(self):
        if self._is_destroyed:
            return
        self._is_destroyed = True
        if self._thread:
            self._thread.stop()

    def __repr__(self):
        return self._config

    def exec(self) -> any:
        """Function to exec the REST function previously specified

        Raises:
            AttributeError: No rest function has been specified

        Returns:
            any: The return type specified in the user-define REST function
        """
        if not hasattr(self._module, "reaction_function_rest"):
            raise AttributeError
        return self._module.reaction_function_rest(self)

    def __getitem__(self, key: str) -> Union[str, Program]:
        """Method to access directly Programs in the class

        Args:
            key (str): The key to search into the Programs dictionary

        Returns:
            Union[str, Program]: the name of the probe for the plugin (key) if Cluster, else the compiled Program
        """
        return self.programs[key] if not self._is_destroyed else exit(1)


class Cluster(BaseEntity):
    """Cluster entity class, to represent a group of probes.

    Args:
        config (ClusterConfig): The cluster configuration
        module (ModuleType): The module containing additional user-defined functions
        programs (ClusterCompilation): The dictionary of probes in the cluster
    """


class Plugin(BaseEntity):
    """Base Class representing all Plugin entities.

    Args:
        config (ProbeConfig): The probe configuration
        module (ModuleType): The module containing additional user-defined functions
        programs (ProbeCompilation): The compiled eBPF programs
    """

    def __init__(self, config: ProbeConfig, module: ModuleType, programs: ProbeCompilation):
        super().__init__(config, module, programs)
        self.__active_hooks: List[str] = []
        for hook in self.__class__.accepted_hooks():
            if config[hook]:
                self.__active_hooks.append(hook)

    def _check_hook_active(self, program_type: str):
        """Function to check whether the probe has a supported hook active

        Args:
            program_type (str): The hook to be checked (ingress/egress)

        Raises:
            HookDisabledException: The hook is not enabled, meaning no eBPF code running
        """
        if program_type not in self.__active_hooks:
            raise HookDisabledException(
                f"The hook {program_type} is not active for this probe")

    def is_in_cluster(self) -> bool:
        """Function to check whether the probe is in a cluster

        Returns:
            bool: True is the probe is in a cluster, else otherwise
        """
        return self._config.is_in_cluster

    @staticmethod
    def accepted_hooks() -> List[str]:
        """Function to check whether the Probe supports both Ingress and Egress hooks

        Returns:
            List[str]: The list of accepted hooks
        """
        return ["ingress", "egress"]

    @staticmethod
    def is_programmable() -> bool:
        """Function to check whether the Probe supports user-defined eBPF code

        Returns:
            bool: True if supported, else otherwise
        """
        return False

    @staticmethod
    def get_cflags() -> List[str]:
        """Method to define per-plugin cflags (if any) to be used while compiling eBPF code.

        Returns:
            List[str]: The list of cflags for the specified Plugin
        """
        return []


class Adaptmon(Plugin):
    """Programmable network probe, accepting user-define eBPF code and Control Plane"""

    @staticmethod
    def is_programmable():
        return True


class Mitigator(Plugin):
    """Mitigator class, an eBPF implementation of an IP/Netmask mitigator."""

    _MAX_IPS = 1000

    def __init__(self, config: ProbeConfig, module: ModuleType, programs: ProbeCompilation):
        super().__init__(config, module, programs)
        self.__rules: List[MitigatorRule] = []

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
            str: The string representation of the rules array
        """
        return dumps(self.__rules)

    def delete_at(self, rule_id: int) -> str:
        """Function to delete a rule at a specific position

        Args:
            rule_id (int): The rule ID

        Raises:
            IndexError: The provided ID is greater than the actual number of rules

        Returns:
            str: The ID of the deleted rule
        """
        if rule_id >= len(self.__rules):
            raise IndexError("The Rule ID provided is wrong")

        rule = self.__rules.pop(rule_id)
        key = LpmKey(rule.netmask, ipv4_to_network_int(rule.ip))

        del self.programs["ingress"]['BLACKLISTED_IPS'][key]
        return str(rule_id)

    def delete(self, rule: MitigatorRule) -> str:
        """Function to delete a rule matching the provided one

        Args:
            rule (MitigatorRule): The Rule to be deleted

        Raises:
            LookupError: The rule is not present

        Returns:
            str: The ID of the deleted rule
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
            str: [description]
        """
        if rule in self.__rules:
            raise LookupError(
                "Attempting to insert a rule which is already present")
        if rule_id > len(self.__rules):
            raise IndexError("The Rule ID provided is wrong")
        if rule_id == Mitigator._MAX_IPS:
            raise MemoryError("You reached the maximum amount of rules")

        key = LpmKey(rule.netmask, ipv4_to_network_int(rule.ip))

        self.programs["ingress"]['BLACKLISTED_IPS'][key] = ct.c_ulong(
            0)
        self.__rules.insert(rule_id, rule)
        return str(rule_id)

    def insert(self, rule: MitigatorRule) -> str:
        """Function to insert a rule without specifying the position (append)

        Args:
            rule (MitigatorRule): The rule to be inserted

        Returns:
            str: The ID of the inserted rule
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
            str: The ID of the updated rule
        """
        if rule in self.__rules:
            raise LookupError(
                "Attempting to update a rule which is already present")
        if rule_id >= len(self.__rules):
            raise IndexError("The Rule ID provided is wrong")
        self.delete_at(rule_id)
        self.insert_at(rule_id, rule)
        return str(rule_id)

    def reset(self) -> str:
        """Function to reset all the rules

        Returns:
            str: The number of deleted rules
        """
        ret = len(self.__rules)
        self.__rules.clear()
        self.programs["ingress"]['BLACKLISTED_IPS'].clear()
        return str(ret)

    @staticmethod
    def get_cflags() -> List[str]:
        return [f'-DMAX_IPS={Mitigator._MAX_IPS}']

    @staticmethod
    def accepted_hooks() -> List[str]:
        return ["ingress"]


class Firewall(Plugin):
    """Firewall class, an eBPF implementation of an iptables-like one."""

    # Size of the eBPF maps, how many entries can they accept
    _RULE_IDS_MAX_ENTRY = 10000
    _MAX_RULES = 100
    # Each entry hosts 64 rules
    _RULE_IDS_WORDS_PER_ENTRY = ceil(_MAX_RULES / 64)
    _MAPS = ['IPV4_SRC', 'IPV4_DST', 'PORT_SRC',
             'PORT_DST', 'IP_PROTO', 'TCP_FLAGS']
    _ALL_MAPS = _MAPS + [f"{x}_WILDCARDS" for x in _MAPS]

    def __init__(self, config: ProbeConfig, module: ModuleType, programs: ProbeCompilation):
        super().__init__(config, module, programs)
        self.__rules: Dict[str, List[FirewallRule]] = {
            "ingress": [],
            "egress": []
        }

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
        self._check_hook_active(program_type), 'PATCH',
        if rule_id >= len(self.__rules):
            raise IndexError("The Rule ID provided is wrong")
        return self.__rules[program_type][rule_id]

    def get(self, program_type: str) -> str:
        """Function to retrieve all the rules for a specific hook

        Args:
            program_type (str): The hook of interest (ingress/egress)

        Returns:
            str: The string representation of the rules array
        """
        self._check_hook_active(program_type)
        return dumps(self.__rules[program_type])

    def delete_at(self, program_type: str, rule_id: int) -> str:
        """Function to delete a rule at a given position (ID)

        Args:
            program_type (str): The hook of interest (ingress/egress)
            rule_id (int): The ID of the rule to be deleted

        Raises:
            IndexError: The provided ID is greater than the number of actual rules

        Returns:
            str: The rule ID
        """
        self._check_hook_active(program_type)
        if rule_id >= len(self.__rules[program_type]):
            raise IndexError("The Rule ID provided is wrong")
        self.__rules[program_type].pop(rule_id)
        word, offset_ok = (rule_id // 64, 64 - rule_id % 64)

        # Foreach map, also for the WILDCARDS ones, iterate through every
        # key-value and shift left the rules by 1, to remove the target one
        for map_name in Firewall._ALL_MAPS:
            for key, value in self.programs[program_type][map_name].items():
                arr = value.rule_words
                cnt_zeros = 0
                carry = 0
                # Starting from right to left
                for w in range(Firewall._RULE_IDS_WORDS_PER_ENTRY - 1, word, -1):
                    cnt_zeros += int(arr[w] == 0)
                    tmp = carry
                    carry = arr[w] >> 63
                    arr[w] = (arr[w] << 1) | tmp
                cnt_zeros += int(arr[word] == 0)
                # If all zeros, then remove the entire entry
                if cnt_zeros == Firewall._RULE_IDS_WORDS_PER_ENTRY:
                    del self.programs[program_type][map_name][key]
                    continue
                # Finishing the current word, which has also the offset into account
                ok = (arr[word] >> offset_ok) << offset_ok
                to_shift = (arr[word] & (pow(2, offset_ok) - 1)) << 1 | carry
                arr[word] = ok | to_shift
                self.programs[program_type][map_name][key] = arr
        self.programs[program_type]['ACTIONS'][ct.c_uint32(
            rule_id)] = ct.c_uint8(BPF.TC_ACT_OK if self._config.mode == BPF.SCHED_CLS else BPF.XDP_PASS)
        return str(rule_id)

    def delete(self, program_type: str, rule: FirewallRule) -> str:
        """Function to delete a rule matching the provided one

        Args:
            program_type (str): The hook of interest (ingress/egress)
            rule (FirewallRule): The rule to be deleted

        Raises:
            LookupError: If the rule does not match any of the present ones

        Returns:
            str: The ID of the deleted rule
        """
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
            str: The ID of the rule
        """
        self._check_hook_active(program_type)
        if rule in self.__rules[program_type]:
            raise LookupError(
                "Attempting to insert a rule which is already present")
        if rule_id > len(self.__rules[program_type]):
            raise IndexError("The Rule ID provided is wrong")
        if rule_id == Firewall._MAX_RULES:
            raise MemoryError("You reached the maximum amount of rules")

        word, offset = (rule_id // 64, 63 - rule_id % 64)
        offset_ok = offset + 1

        # If the id is in the middle of the list, then all the following rules has
        # to be shifted right by 1, for each map (also WILDCARDS)
        if rule_id < len(self.__rules[program_type]):
            for map_name in Firewall._ALL_MAPS:
                for key, value in self.programs[program_type][map_name].items():
                    # Starting from left to right, thus the 1st word has also the offset
                    # into account
                    arr = value.rule_words
                    carry = arr[word] & 1
                    ok = (arr[word] >> offset_ok) << offset_ok
                    to_shift = (arr[word] & (pow(2, offset_ok) - 1)) >> 1
                    arr[word] = ok | to_shift
                    # Finishing all the other words
                    for w in range(word + 1, Firewall._RULE_IDS_WORDS_PER_ENTRY):
                        tmp = carry
                        carry = arr[w] & 1
                        arr[w] = (arr[w] >> 1) | (tmp << 63)
                    self.programs[program_type][map_name][key] = arr

        # Insert into the maps, at the specific position the value 1, according
        # to the values specified in the rule
        for map_name, value in zip(Firewall._MAPS, Firewall.translate_rule(rule)):
            if value is None:
                map_name = f'{map_name}_WILDCARDS'
                value = 0
            if value in self.programs[program_type][map_name]:
                arr = self.programs[program_type][map_name][value].rule_words
            else:
                arr = (ct.c_uint64 * Firewall._RULE_IDS_WORDS_PER_ENTRY)()
            arr[word] |= (1 << offset)
            self.programs[program_type][map_name][value] = arr
        self.programs[program_type]['ACTIONS'][ct.c_uint32(
            rule_id)] = ct.c_uint8(BPF.TC_ACT_SHOT if self._config.mode == BPF.SCHED_CLS else BPF.XDP_DROP)
        self.__rules[program_type].insert(rule_id, rule)
        return str(rule_id)

    def insert(self, program_type: str, rule: FirewallRule) -> str:
        """Function to insert the rule given no position (append)

        Args:
            program_type (str): The hook of interest (ingress/egress)
            rule (FirewallRule): The rule to be inserted

        Returns:
            str: The rule ID
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
            str: The id of the rule
        """
        if rule in self.__rules[program_type]:
            raise LookupError(
                "Attempting to update a rule which is already present")
        if rule_id >= len(self.__rules[program_type]):
            raise IndexError("The Rule ID provided is wrong")
        self.delete_at(program_type, rule_id)
        self.insert_at(program_type, rule_id, rule)
        return str(rule_id)

    def reset(self, program_type: str) -> str:
        """Function to reset the rules of the Firewall instance

        Args:
            program_type (str): The hook of interest (ingress/egress)

        Returns:
            [str]: The number of rules erased
        """
        self._check_hook_active(program_type)
        ret = len(self.__rules[program_type])
        self.__rules[program_type].clear()
        for map_name in Firewall._ALL_MAPS:
            self.programs[program_type][map_name].clear()
        return str(ret)

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

    @staticmethod
    def get_cflags() -> List[str]:
        return [
            '-DFW_ACTION_DEFAULT=DROP',
            f'-DRULE_IDS_MAX_ENTRY={Firewall._RULE_IDS_MAX_ENTRY}',
            f'-DMAX_RULES={Firewall._MAX_RULES}',
            f'-DRULE_IDS_WORDS_PER_ENTRY={Firewall._RULE_IDS_WORDS_PER_ENTRY}']
