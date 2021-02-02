Module dechainy.routes.mitigator
================================

Functions
---------

    
`manage_blacklist(probe_name: str) ‑> Union[List[dechainy.configurations.MitigatorRule], str]`
:   Rest endpoint to get, create or delete a given rule of a specific Mitigator instance
    
    Args:
        probe_name (str): The name of the Mitigator instance
    
    Returns:
        Union[List[MitigatorRule], str]: The rules if GET request, else the ID of the deleted/modified one

    
`manage_rule_at(probe_name: str, rule_id: int) ‑> Union[dechainy.configurations.MitigatorRule, str]`
:   Rest endpoint to create, modify or delete a rule given its ID, on a specific Mitigator instance
    
    Args:
        probe_name (str): The name of the Mitigator instance
        id (int): The rule ID
    
    Returns:
        Union[MitigatorRule, str]: The rule if GET request, else its ID

    
`reset_rules(probe_name: str) ‑> str`
:   Rest endpoint used to reset the rules of a specific Mitigator instance
    
    Args:
        probe_name (str): The name of the Firewall instance
        program_type (str): The hook of interes (ingress/egress)
    
    Returns:
        str: The number of rules deleted