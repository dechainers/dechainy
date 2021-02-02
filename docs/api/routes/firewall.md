Module dechainy.routes.firewall
===============================

Functions
---------

    
`manage_rule_at(probe_name: str, program_type: str, id: int) ‑> Union[dechainy.configurations.FirewallRule, str]`
:   Rest endpoint to create, modify or delete a rule given its ID, on a specific Firewall instance's hook
    
    Args:
        probe_name (str): The name of the Firewall instance
        program_type (str): The hook of interes (ingress/egress)
        id (int): The rule ID
    
    Returns:
        Union[FirewallRule, str]: The rule if GET request, else its ID

    
`manage_rules(probe_name: str, program_type: str) ‑> Union[List[dechainy.configurations.FirewallRule], str]`
:   Rest endpoint to get, create or delete a given rule on a specific Firewall instance's hook
    
    Args:
        probe_name (str): The name of the Firewall instance
        program_type (str): The hook of interes (ingress/egress)
    
    Returns:
        Union[List[FirewallRule], str]: The rules if GET request, else the ID of the deleted/modified one

    
`reset_rules(probe_name: str, program_type: str) ‑> str`
:   Rest endpoint used to reset the rules of a specific Firewall instance's hook
    
    Args:
        probe_name (str): The name of the Firewall instance
        program_type (str): The hook of interes (ingress/egress)
    
    Returns:
        str: The number of rules deleted