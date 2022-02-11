from dataclasses import dataclass

from dechainy.plugins import Probe


@dataclass
class Invalid1(Probe):
    pass
