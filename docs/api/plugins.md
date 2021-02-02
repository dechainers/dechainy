Module dechainy.plugins
=======================

Classes
-------

`Adaptmon(config: dechainy.configurations.ProbeConfig, module: module, programs: dechainy.configurations.ProbeCompilation)`
:   Programmable network probe, accepting user-define eBPF code and Control Plane

    ### Ancestors (in MRO)

    * dechainy.plugins.Plugin
    * dechainy.plugins.BaseEntity

`BaseEntity(config: Union[dechainy.configurations.ProbeConfig, dechainy.configurations.ClusterConfig], module: module, programs: Union[dechainy.configurations.ProbeCompilation, dechainy.configurations.ClusterCompilation])`
:   Base class to define an entity (Plugin or Cluster) with many properties in common.
    
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

    ### Descendants

    * dechainy.plugins.Cluster
    * dechainy.plugins.Plugin

    ### Static methods

    `get_cflags() ‑> List[str]`
    :   Method to define per-plugin cflags (if any) to be used while compiling eBPF code.
        
        Returns:
            List[str]: The list of cflags for the specified Plugin

    ### Methods

    `exec(self) ‑> <built-in function any>`
    :   Function to exec the REST function previously specified
        
        Raises:
            AttributeError: No rest function has been specified
        
        Returns:
            any: The return type specified in the user-define REST function

`Cluster(config: Union[dechainy.configurations.ProbeConfig, dechainy.configurations.ClusterConfig], module: module, programs: Union[dechainy.configurations.ProbeCompilation, dechainy.configurations.ClusterCompilation])`
:   Cluster entity class, to represent a group of probes.
    
    Args:
        config (ClusterConfig): The cluster configuration
        module (ModuleType): The module containing additional user-defined functions
        programs (ClusterCompilation): The dictionary of probes in the cluster

    ### Ancestors (in MRO)

    * dechainy.plugins.BaseEntity

`Firewall(config: dechainy.configurations.ProbeConfig, module: module, programs: dechainy.configurations.ProbeCompilation)`
:   Firewall class, an eBPF implementation of an iptables-like one.

    ### Ancestors (in MRO)

    * dechainy.plugins.Plugin
    * dechainy.plugins.BaseEntity

    ### Static methods

    `translate_rule(rule: dechainy.configurations.FirewallRule) ‑> List[<built-in function any>]`
    :   Static function to translate a rule into values ready to be inserted in the eBPF maps.
        
        Args:
            rule (FirewallRule): The rule to be converted
        
        Returns:
            List[any]: List of converted fields using ctypes

    ### Methods

    `delete(self, program_type: str, rule: dechainy.configurations.FirewallRule) ‑> str`
    :   Function to delete a rule matching the provided one
        
        Args:
            program_type (str): The hook of interest (ingress/egress)
            rule (FirewallRule): The rule to be deleted
        
        Raises:
            LookupError: If the rule does not match any of the present ones
        
        Returns:
            str: The ID of the deleted rule

    `delete_at(self, program_type: str, rule_id: int) ‑> str`
    :   Function to delete a rule at a given position (ID)
        
        Args:
            program_type (str): The hook of interest (ingress/egress)
            rule_id (int): The ID of the rule to be deleted
        
        Raises:
            IndexError: The provided ID is greater than the number of actual rules
        
        Returns:
            str: The rule ID

    `get(self, program_type: str) ‑> str`
    :   Function to retrieve all the rules for a specific hook
        
        Args:
            program_type (str): The hook of interest (ingress/egress)
        
        Returns:
            str: The string representation of the rules array

    `get_at(self, program_type: str, rule_id: int) ‑> dechainy.configurations.FirewallRule`
    :   Function to retrieve a rule at a specific position
        
        Args:
            program_type (str): The hook of interest (ingress/egress)
            rule_id (int): The ID of the rule
        
        Raises:
            IndexError: The provided ID is greater than the actual number of rules
        
        Returns:
            FirewallRule: The retrieved rule

    `insert(self, program_type: str, rule: dechainy.configurations.FirewallRule) ‑> str`
    :   Function to insert the rule given no position (append)
        
        Args:
            program_type (str): The hook of interest (ingress/egress)
            rule (FirewallRule): The rule to be inserted
        
        Returns:
            str: The rule ID

    `insert_at(self, program_type: str, rule_id: int, rule: dechainy.configurations.FirewallRule) ‑> str`
    :   Function to insert a rule at a given position. All the following ones are shifted
        
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

    `reset(self, program_type: str) ‑> str`
    :   Function to reset the rules of the Firewall instance
        
        Args:
            program_type (str): The hook of interest (ingress/egress)
        
        Returns:
            [str]: The number of rules erased

    `update(self, program_type: str, rule_id: int, rule: dechainy.configurations.FirewallRule) ‑> str`
    :   Function to update a specific rule given its ID
        
        Args:
            program_type (str): The hook of interest (ingress/egress)
            rule_id (int): The ID of the rule to be updated
            rule (FirewallRule): The new rule to be inserted
        
        Raises:
            LookupError: The new rule is already present
            IndexError: The rule ID is greater than the actual number of rules
        
        Returns:
            str: The id of the rule

`Mitigator(config: dechainy.configurations.ProbeConfig, module: module, programs: dechainy.configurations.ProbeCompilation)`
:   Mitigator class, an eBPF implementation of an IP/Netmask mitigator.

    ### Ancestors (in MRO)

    * dechainy.plugins.Plugin
    * dechainy.plugins.BaseEntity

    ### Methods

    `delete(self, rule: dechainy.configurations.MitigatorRule) ‑> str`
    :   Function to delete a rule matching the provided one
        
        Args:
            rule (MitigatorRule): The Rule to be deleted
        
        Raises:
            LookupError: The rule is not present
        
        Returns:
            str: The ID of the deleted rule

    `delete_at(self, rule_id: int) ‑> str`
    :   Function to delete a rule at a specific position
        
        Args:
            rule_id (int): The rule ID
        
        Raises:
            IndexError: The provided ID is greater than the actual number of rules
        
        Returns:
            str: The ID of the deleted rule

    `get(self) ‑> str`
    :   Function to retrieve all the rules
        
        Returns:
            str: The string representation of the rules array

    `get_at(self, rule_id: int) ‑> dechainy.configurations.MitigatorRule`
    :   Function to retrieve a rule at a specific position
        
        Args:
            rule_id (int): The ID of the rule to be retrieved
        
        Raises:
            IndexError: The ID is greater than the actual number of rules
        
        Returns:
            MitigatorRule: The rule retrieved

    `insert(self, rule: dechainy.configurations.MitigatorRule) ‑> str`
    :   Function to insert a rule without specifying the position (append)
        
        Args:
            rule (MitigatorRule): The rule to be inserted
        
        Returns:
            str: The ID of the inserted rule

    `insert_at(self, rule_id: int, rule: dechainy.configurations.MitigatorRule) ‑> str`
    :   Function to insert a rule at a specific position
        
        Args:
            rule_id (int): The ID of the rule
            rule (MitigatorRule): The rule to be inserted
        
        Raises:
            LookupError: If already exists a similar rule
            IndexError: If the provided ID is greater than the actual number of rules
            MemoryError: If there is no enough room for a new rule
        
        Returns:
            str: [description]

    `reset(self) ‑> str`
    :   Function to reset all the rules
        
        Returns:
            str: The number of deleted rules

    `update(self, rule_id: int, rule: dechainy.configurations.MitigatorRule) ‑> str`
    :   Function to update a rule at a specific position
        
        Args:
            rule_id (int): The ID of the rule to be updated
            rule (MitigatorRule): The new rule to be inserted
        
        Raises:
            LookupError: There is already a rule like the provided one
            IndexError: The ID is greater than the actual number of rules
        
        Returns:
            str: The ID of the updated rule

`Plugin(config: dechainy.configurations.ProbeConfig, module: module, programs: dechainy.configurations.ProbeCompilation)`
:   Base Class representing all Plugin entities.
    
    Args:
        config (ProbeConfig): The probe configuration
        module (ModuleType): The module containing additional user-defined functions
        programs (ProbeCompilation): The compiled eBPF programs

    ### Ancestors (in MRO)

    * dechainy.plugins.BaseEntity

    ### Descendants

    * dechainy.plugins.Adaptmon
    * dechainy.plugins.Firewall
    * dechainy.plugins.Mitigator

    ### Static methods

    `accepted_hooks() ‑> List[str]`
    :   Function to check whether the Probe supports both Ingress and Egress hooks
        
        Returns:
            List[str]: The list of accepted hooks

    `is_programmable() ‑> bool`
    :   Function to check whether the Probe supports user-defined eBPF code
        
        Returns:
            bool: True if supported, else otherwise

    ### Methods

    `is_in_cluster(self) ‑> bool`
    :   Function to check whether the probe is in a cluster
        
        Returns:
            bool: True is the probe is in a cluster, else otherwise