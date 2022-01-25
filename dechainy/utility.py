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
import re
import os
import signal
import time
import socket
import logging

from socket import inet_aton, htons, ntohs, inet_ntoa
from struct import unpack
from multiprocessing import Process
from threading import Event, Thread
from typing import Callable


class Singleton(type):
    """Metatype utility class to define a Singleton Pattern

    Attributes:
        _instance(object): The instance of the Singleton
    """
    _instance: object = None

    def __call__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instance


class CPProcess(Process):
    """Utility class to create a Process (stopped when destroying its proprietary)
    to execute a function locally every time_window.

    Args:
        target_fun (Callable): The function to execute periodically
        ent (BaseEntity): The entity which invoked the function
        time_window (int): The periodic restart value
        name (str): The name of the created process
        daemon (bool): The daemon mode. Default False.
    """

    def __init__(self, target_fun: Callable, ent, time_window: float, daemon: bool = False):
        Process.__init__(self, target=self.cp_run, args=(
            target_fun, ent, time_window,), daemon=daemon)

    def stop(self):
        """Function called by the proprietary to stop the Process"""
        os.kill(self.pid, signal.SIGINT)

    def cp_run(self, target_fun, ent, time_window):
        """Function to execute the provided function, if no stop signal registered within the time_window provided."""
        while True:
            time.sleep(time_window)
            target_fun(ent) if ent else target_fun()


class CPThread(Thread):
    """Utility class to create a daemon thread (stopped when destroying its proprietary)
    to execute a function locally every time_window.
    Args:
        target (Callable): The function to execute
        args (tuple): The arguments provided
        timeout (int): The periodic restart value
    Attributes:
        func (Callable): The function to be executed
        args (tuple): The arguments provided to the function
        time_window (int): The timeout used for the thread to re-start
    """
    def __init__(self, target_fun: Callable, ent, time_window: float, daemon: bool = False):
        self.__stop_event: Event = Event()
        Thread.__init__(self, target=self.cp_run, args=(
            target_fun, ent, time_window,), daemon=daemon)

    def stop(self):
        """Function called by the proprietary to stop the Thread"""
        self.__stop_event.set()

    def cp_run(self, target_fun, ent, time_window):
        """Function to execute the provided function, if no stop signal registered within the time_window provided."""
        while not self.__stop_event.wait(time_window):
            target_fun(ent) if ent else target_fun()


def remove_c_comments(text: str) -> str:
    """Function to remove C-like comments, working also in trickiest cases
    [New] Useful link: https://gist.github.com/ChunMinChang/88bfa5842396c1fbbc5b
    [Old] Useful link: https://stackoverflow.com/questions/36454069/how-to-remove-c-style-comments-from-code

    Args:
        text (str): the original text with comments

    Returns:
        str: the string sanitized from comments
    """
    def replacer(match):
        s = match.group(0)
        # note: a space and not an empty string
        return " " if s.startswith('/') else s
    pattern = re.compile(
        r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"',
        re.DOTALL | re.MULTILINE
    )
    return re.sub(pattern, replacer, text)


__proto_int_to_str = {num:name[8:] for name,num in vars(socket).items() if name.startswith("IPPROTO")}


def protocol_to_int(name: str) -> int:
    """Function to return the integer value of a protocol given its name

    Args:
        name (str): the name of the protocol

    Returns:
        int: the integer value of the protocol
    """
    return socket.getprotobyname(name)


def protocol_to_string(value: int) -> str:
    """Function to return the name of the protocol given its integer value

    Args:
        value (int): the value of the protocol

    Raises:
        Exception: the protocol has not been added to the map

    Returns:
        str: the name of the protocol
    """
    return __proto_int_to_str[value]


def ipv4_to_network_int(address: str) -> int:
    """Function to conver an IPv4 address string into network byte order integer

    Args:
        address (str): the addess to be converted

    Returns:
        int: the big endian representation of the address
    """
    return unpack('<I', inet_aton(address))[0]


def port_to_network_int(port: int) -> int:
    """Function to conver a port (integer) into its big endian representation

    Args:
        port (int): the value of the port

    Returns:
        int: the big endian representation of the port
    """
    return htons(port)


def ipv4_to_string(address: int) -> str:
    """Function to convert an IP address from its big endian format to string

    Args:
        address (int): the address expressed in big endian

    Returns:
        str: the address as string
    """
    return inet_ntoa(address.to_bytes(4, 'little'))


def port_to_host_int(port: int) -> int:
    """Function to convert a port from network byte order to little endian

    Args:
        port (int): the big endian port to be converted

    Returns:
        int: the little endian representation of the port
    """
    return ntohs(port)


def ctype_to_normal(obj: any) -> any:
    """Function to convert a ctype object into a Python Serializable one

    Args:
        obj (any): The ctypes object to be converted

    Returns:
        any: The object converted
    """
    if obj is None:
        return obj

    if isinstance(obj, (bool, int, float, str)):
        return obj

    if isinstance(obj, (ct.Array, list)):
        return [ctype_to_normal(e) for e in obj]

    if isinstance(obj, ct._Pointer):
        return ctype_to_normal(obj.contents) if obj else None

    if isinstance(obj, ct._SimpleCData):
        return ctype_to_normal(obj.value)

    if isinstance(obj, (ct.Structure, ct.Union)):
        result = {}
        anonymous = getattr(obj, '_anonymous_', [])

        for key, _ in getattr(obj, '_fields_', []):
            value = getattr(obj, key)

            # private fields don't encode
            if key.startswith('_'):
                continue

            if key in anonymous:
                result.update(ctype_to_normal(value))
            else:
                result[key] = ctype_to_normal(value)

        return result


def get_logger(name, filepath=None, log_level: int = logging.INFO):
    logger = logging.getLogger(name)
    logger.setLevel(log_level)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handlers = [logging.StreamHandler()]
    if filepath:
        handlers.append(logging.FileHandler(filepath, mode="w"))
    for h in handlers:
        h.setLevel(log_level)
        h.setFormatter(formatter)
        logger.addHandler(h)
    return logger


def log_and_raise(logger, msg: str, exception: Exception = Exception):
    logger.error(msg)
    raise exception(msg)