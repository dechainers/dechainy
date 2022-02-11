from dataclasses import dataclass

from dechainy.plugins import Probe
from dechainy.ebpf import EbpfCompiler, ProbeCompilation


@dataclass
class Valid(Probe):

    def __post_init__(self):
        self.ingress.required = True
        self.ingress.cflags.append("-DCUSTOM_VARIABLE=0")
        self.egress.required = False
        super().__post_init__(path=__file__)

    def post_compilation(self, comp: ProbeCompilation):
        return super().post_compilation(comp)

    def autopatch(self):
        self.ingress.cflags[-1] = "-DCUSTOM_VARIABLE=1"
        EbpfCompiler().patch_hook("ingress", self._programs.ingress,
                                  self.ingress.code, self.ingress.cflags)
