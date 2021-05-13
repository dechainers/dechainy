Module dechainy.routes.adaptmon
===============================

Functions
---------

    
`retrieve_metric(probe_name: str, program_type: str, metric_name: str) ‑> <built-in function any>`
:   Rest endpoint to retrieve the value of a defined metric
    
    Args:
        probe_name (str): The name of the Adaptmon instance
        program_type (str): The type of the program (Ingress/Egress)
        metric_name (str): The name of the metric to be retrieved
    
    Returns:
        any: The value of the metric

    
`retrieve_metrics(probe_name: str, program_type: str) ‑> <built-in function any>`
:   Rest endpoint to retrieve the value of all metrics
    
    Args:
        probe_name (str): The name of the Adaptmon instance
        program_type (str): The type of the program (Ingress/Egress)
    
    Returns:
        any: The value of the metrics