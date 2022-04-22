# Copyright 2022 DeChainers
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
import argparse
import os
import time
import ctypes as ct

from types import ModuleType
from typing import Dict

from bcc import BPF

# Pivoting code to forward packet to the currently active eBPF program
swap_pivot = """
BPF_TABLE("prog", int, int, ACTIVE_PROGRAM, 1);

int handle_rx(struct CTXTYPE *ctx) {
  ACTIVE_PROGRAM.call(ctx, 0);
  return RX_OK;
}
"""

# Retrieving the value used to compute UNIX Time in eBPF
with open('/proc/uptime', 'r') as f:
    EPOCH_BASE = int(
        (int(time.time() * 10**9) - int(float(f.readline().split()[0]) * (10 ** 9))))

# Cflags passed to the eBPF programs
cflags = ["-DCTXTYPE=xdp_md",
          f"-DRX_OK={BPF.XDP_PASS}", f"-DEPOCH_BASE={EPOCH_BASE}"]


def parse_arguments() -> Dict[str, any]:
    """Function called to parse argument passed to this main file

    Returns:
        Dict[str, any]: The dictionary with the arguments provided
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument(
        'interface', help='The interface to which attach the eBPF program', type=str)
    parser.add_argument(
        '-b', '--bpf', help='The path to the eBPF source code', type=str, default=f"{os.getcwd()}/ebpf.c")
    parser.add_argument(
        '-m', '--model', help='The path to the Lucid model', type=str, default=f"{os.getcwd()}/model.h5")
    parser.add_argument(
        '-e', '--extractor', help='The path to the Extractor module', type=str, default=f"{os.getcwd()}/extract.py")
    parser.add_argument(
        '-t', '--time_window', help='The time window used both for eBPF extraction and NN models',
        type=int, default=10)
    parser.add_argument(
        '-x', '--xdp_mode', help='The XDP mode used (XDP_SKB = 1 << 1, XDP_DRV = 1 << 2, XDP_HW = 1 << 3)',
        type=int, default=(1 << 1))
    return parser.parse_args().__dict__


def main():
    global swap_pivot, cflags

    args = parse_arguments()
    src_ebpf = args["bpf"]
    device = args["interface"]
    time_window = args["time_window"]
    xdp_mode = args["xdp_mode"]

    # Loading Extractor by reading the file, to avoid that it belongs
    # to a non-python directory
    with open(args["extractor"], 'r') as fp:
        module = ModuleType("extractor")
        exec(fp.read(), module.__dict__)

    # Initializing models and time window the the other module
    module.init(args["model"], time_window)

    # Compiling and loading pivoting code
    pivot = BPF(text=swap_pivot, cflags=cflags)
    f = pivot.load_func('handle_rx', BPF.XDP)

    try:
        pivot.attach_xdp(device, f, xdp_mode)
    except Exception:
        # Driver does not support the provided XDP mode, using SBK
        pivot.attach_xdp(device, f, (1 << 1))

    # Compiling two parallel programs and loading functions
    programs = [BPF(src_file=src_ebpf, cflags=cflags),
                BPF(src_file=src_ebpf, cflags=cflags)]
    fds = [x.load_func('handle_rx', BPF.XDP).fd for x in programs]

    # Set the initial index to the 1st program
    index = 0
    pivot["ACTIVE_PROGRAM"][0] = ct.c_int(fds[index])

    while True:
        try:
            time.sleep(time_window)
            # Swap the programs
            program_off = programs[index]
            index = (index + 1) % 2
            pivot["ACTIVE_PROGRAM"][0] = ct.c_int(fds[index])
            # Read maps of the offline program
            module.read_program_maps(program_off)
        except KeyboardInterrupt:
            break

    # Remove the only injected one, the pivoting program
    pivot.remove_xdp(device, xdp_mode)


if __name__ == '__main__':
    main()
