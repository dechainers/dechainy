Module dechainy.exceptions
==========================

Classes
-------

`ClusterNotFoundException(*args, **kwargs)`
:   Exception to be thrown when the desired Cluster has not been found

    ### Ancestors (in MRO)

    * builtins.Exception
    * builtins.BaseException

`HookDisabledException(*args, **kwargs)`
:   Exception to be thrown when performing operations on a hook that has been disabled in the probe config

    ### Ancestors (in MRO)

    * builtins.Exception
    * builtins.BaseException

`MissingInterfaceInProbeException(*args, **kwargs)`
:   Exception to be thrown when the Interface is not specified in the Probe Configuration

    ### Ancestors (in MRO)

    * builtins.Exception
    * builtins.BaseException

`NoCodeProbeException(*args, **kwargs)`
:   Exception to be thrown when creating a probe without at least 1 program type active

    ### Ancestors (in MRO)

    * builtins.Exception
    * builtins.BaseException

`PluginNotFoundException(*args, **kwargs)`
:   Exception to be thrown when the desired Plugin has not been found

    ### Ancestors (in MRO)

    * builtins.Exception
    * builtins.BaseException

`ProbeAlreadyExistsException(*args, **kwargs)`
:   Exception to be thrown when the desired Probe already exists in the system

    ### Ancestors (in MRO)

    * builtins.Exception
    * builtins.BaseException

`ProbeInClusterException(*args, **kwargs)`
:   Exception to be thrown when the desired plugin to delete is in a Cluster

    ### Ancestors (in MRO)

    * builtins.Exception
    * builtins.BaseException

`ProbeNotFoundException(*args, **kwargs)`
:   Exception to be thrown when the desired Probe has not been found

    ### Ancestors (in MRO)

    * builtins.Exception
    * builtins.BaseException

`UnknownInterfaceException(*args, **kwargs)`
:   Exception to be thrown when the desired Interface does not exist

    ### Ancestors (in MRO)

    * builtins.Exception
    * builtins.BaseException

`UnsupportedOperationException(*args, **kwargs)`
:   Exception to be thrown when requiring an endpoint (e.g., "/exec") not supported by the probe/cluster

    ### Ancestors (in MRO)

    * builtins.Exception
    * builtins.BaseException