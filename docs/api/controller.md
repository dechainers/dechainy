Module dechainy.controller
==========================

Classes
-------

`Controller(log_level=20)`
:   Class (Singleton) for managing deployed and available resources.
    
    Static Attributes:
        _plugins_lock(RLock): The mutex for the plugins.
        _logger (Logger): The class logger.
    
    Attributes:
        __probes (Dict[str, Dict[str, Type[Probe]]]): A dictionary containing, for each plugin,
            an inner dictionary holding the dictionary of the current deployed probes.
        __observer (Observer): Watchdog thread to keep this instance synchronised with
            the plugin directory.
        __compiler (EbpfCompiler): An instance of the eBPF programs compiler, to prevent
            it to be destroyed in the mean time.

    ### Static methods

    `check_plugin_validity(plugin_name: str)`
    :   Static method to check the validity of a plugin. Validity conditions are:
        1. in the __init__.py there is a class representing the plugin with the
            capitalized name of the plugin (e.g., johndoe -> Johndoe);
        2. such class needs to extend the superclass Probe;
        3. such class needs to be a dataclass.
        
        Args:
            plugin_name (str, optional): The name of the plugin.
        
        Raises:
            exceptions.InvalidPluginException: When one of the validity condition
                is violated.

    `create_plugin(variable: str, update: bool = False)`
    :   Static method to create a plugin. Different types are supported:
        1. local directory: path to a local plugin directory;
        2. remote custom: URL to the remote repository containing the plugin to pull;
        3. remote default: the plugin is pulled from the default dechainy_plugin_<name> repo.
        
        Raises:
            exceptions.UnknownPluginFormatException: When none of the above formats is provided.

    `delete_plugin(plugin_name: str = None)`
    :   Static method to delete a plugin. If the name is not specified,
        then all the plugins are deleted.
        
        Args:
            plugin_name (str, optional): The name of the plugin. Defaults to None.
        
        Raises:
            exceptions.PluginNotFoundException: When the plugin does not exist.

    `get_plugin(plugin_name: str = None) ‑> Union[module, List[module]]`
    :   Static method to return the Module of the requested plugin. If the name
        is not provided, then all the available plugins are loaded and returned.
        
        Args:
            plugin_name (str, optional): The name of the plugin. Defaults to None.
        
        Returns:
            Union[ModuleType, List[ModuleType]]: The list of loaded modules or the
                target one.

    ### Methods

    `create_probe(self, plugin_name: str, probe_name: str, **kwargs)`
    :   Method to create the given probe.
        
        Args:
            probe (Probe): The probe to be created.
        
        Raises:
            exceptions.PluginNotFoundException: When the plugin does not exist.
            exceptions.ProbeAlreadyExistsException: When a probe of the same plugin
                and having the same name already exists.

    `delete_probe(self, plugin_name: str = None, probe_name: str = None)`
    :   Method to delete probes. If the plugin name is not specified, then
        all the probes deployed are deleted. Otherwise, all the probes belonging
        to that plugins are deleted, or the target one if also the probe name
        is specified.
        
        Args:
            plugin_name (str, optional): The name of the plugin. Defaults to None.
            probe_name (str, optional): The name of the probe. Defaults to None.
        
        Raises:
            exceptions.ProbeNotFoundException: When the probe does not exist
            exceptions.PluginNotFoundException: When the plugin does not exist.

    `get_probe(self, plugin_name: str = None, probe_name: str = None) ‑> Union[Dict[str, Dict[str, Type[dechainy.plugins.Probe]]], Dict[str, Type[dechainy.plugins.Probe]], Type[dechainy.plugins.Probe]]`
    :   Function to retrieve probes. If the plugin name is not specified, then
        all the probes deployed in the system are returned. Otherwise return all the probes belonging
        to that plugin, or just the target one if also the probe name is specified.
        
        Args:
            plugin_name (str, optional): The name of the plugin. Defaults to None.
            probe_name (str, optional): The name of the probe. Defaults to None.
        
        Raises:
            exceptions.ProbeNotFoundException: The requested probe has not been found.
            exceptions.PluginNotFoundException: The requested plugin has not been found.
        
        Returns:
            Union[Dict[str, Dict[str, Type[Probe]]], Dict[str, Type[Probe]], Type[Probe]]: The Dictionary of all
                probes, or the dictionary of probes of a specific plugin, or the target probe.

    `sync_plugin_probes(self, plugin_name: str)`
    :   Method to remove all the probes belonging to the deleted plugin, if any.
        
        Args:
            plugin_name (str): The name of the plugin deleted.

`SyncPluginsHandler()`
:   Watchdog class for file system modification to plugins and
    synchronization with the current deployed resources.
    If a plugin is removed from the directory, this component
    automatically removes all the probes of that plugin for
    coherency.

    ### Ancestors (in MRO)

    * watchdog.events.FileSystemEventHandler

    ### Methods

    `on_created(self, event: watchdog.events.FileSystemEvent)`
    :   Method to be called when a directory in the plugin
        folder is created, whether it is a legitimate plugin
        or not. If not already checked, this methods forces
        the Controller to check the newly created Plugin validity.
        
        Args:
            event (FileSystemEvent): The base event.

    `on_deleted(self, event: watchdog.events.FileSystemEvent)`
    :   Function to be called everytime a directory is removed
        from the plugin folder, whether it is a legitimate plugin or
        not. This method enforces the Controller to check whether there
        are probes of that plugin deployed, and in case remove them.
        
        Args:
            event (FileSystemEvent): The base event