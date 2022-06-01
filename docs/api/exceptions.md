Module dechainy.exceptions
==========================

Classes
-------

`HookDisabledException(*args, **kwargs)`
:   Exception to be thrown when performing operations on a hook that has been disabled in the probe config

    ### Ancestors (in MRO)

    * builtins.Exception
    * builtins.BaseException

`InvalidPluginException(*args, **kwargs)`
:   Exception to be thrown when Plugin is not compliant

    ### Ancestors (in MRO)

    * builtins.Exception
    * builtins.BaseException

`MetricUnspecifiedException(*args, **kwargs)`
:   Exception to be thrown when requiring a specific metric not specified in the Adaptmon code

    ### Ancestors (in MRO)

    * builtins.Exception
    * builtins.BaseException

`NoCodeProbeException(*args, **kwargs)`
:   Exception to be thrown when creating a probe without at least 1 program type active

    ### Ancestors (in MRO)

    * builtins.Exception
    * builtins.BaseException

`PluginAlreadyExistsException(*args, **kwargs)`
:   Exception to be thrown when the desired Plugin to create already exists

    ### Ancestors (in MRO)

    * builtins.Exception
    * builtins.BaseException

`PluginNotFoundException(*args, **kwargs)`
:   Exception to be thrown when the desired Plugin has not been found

    ### Ancestors (in MRO)

    * builtins.Exception
    * builtins.BaseException

`PluginUrlNotValidException(*args, **kwargs)`
:   Exception to be thrown when the url of the desired Plugin to download is not valid

    ### Ancestors (in MRO)

    * builtins.Exception
    * builtins.BaseException

`ProbeAlreadyExistsException(*args, **kwargs)`
:   Exception to be thrown when the desired Probe already exists in the system

    ### Ancestors (in MRO)

    * builtins.Exception
    * builtins.BaseException

`ProbeNotFoundException(*args, **kwargs)`
:   Exception to be thrown when the desired Probe has not been found

    ### Ancestors (in MRO)

    * builtins.Exception
    * builtins.BaseException

`ProgramInChainNotFoundException(*args, **kwargs)`
:   Exception to be thrown when the specified program has not been fond in the chain

    ### Ancestors (in MRO)

    * builtins.Exception
    * builtins.BaseException

`UnknownInterfaceException(*args, **kwargs)`
:   Exception to be thrown when the desired Interface does not exist

    ### Ancestors (in MRO)

    * builtins.Exception
    * builtins.BaseException

`UnknownPluginFormatException(*args, **kwargs)`
:   Exception to be thrown when Plugin format not recognized or supported

    ### Ancestors (in MRO)

    * builtins.Exception
    * builtins.BaseException