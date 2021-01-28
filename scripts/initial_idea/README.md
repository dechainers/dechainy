# Initial Idea

Initial idea of the framework.

## Story

After my MSc Thesis, the idea of performing dynamic eBPF programs injection was a constant thought in my mind, but the results achieved were not so exciting, due to the parsing time of eBPF maps. I then decided to create two scripts by myself: an injector and an extractor, written in Python, which is loosely typed, and allows users to deal with any data type with less pain than using a strictly typed language, like C++.

This idea led to better results, and from that moment on I decided I could create something bigger, an entire framework, to use multiple eBPF programs instead of a single one. Obviously, this first scripts has helped me to understand what a potential user could need, implementing features that increases performance.

## Installation

The entire eBPF program compilation depends on BCC, which may be installed locally or on a Docker environment. However, when using the BCC provided by the main apt repository, you cannot access to the latest releases, thus you cannot use some newer data structure like BPF_QUEUE/BPF_STACK and other helpers.

As a result, I decided to manually take the entire BCC framework, compile it within a Docker where I also copy the source scripts I created to run this program. To compile the Docker, type:

```bash
user@ubuntu $ ~ docker build -t s41m0n/adaptive:latest .
```

Then you are ready to try it out.

## Usage

The [injector.py](injector.py) script, a very powerful script to inject into a user-defined network interface an XDP program. Actually, the scripts inject a pivoting code, which will redirect the packet to the correct program. This has been introduced since SWAP of programs is performed: instead of compiling only the desired eBPF program, I clone it and compile also the cloned one. Then, whenever the time window expires, I swap out the current active program with the "offline" one, in order to obtain atomicity when reading maps, since the running eBPF is different than the maps we are reading from the swapped-out program.

Here follows a list of argument accepted by the program:

```bash
usage: injector.py [-h] [-b BPF] [-m MODEL] [-e EXTRACTOR] [-t TIME_WINDOW]
                   [-x XDP_MODE]
                   interface

positional arguments:
  interface             The interface to which attach the eBPF program

optional arguments:
  -h, --help            show this help message and exit
  -b BPF, --bpf BPF     The path to the eBPF source code (default:
                        /tmp/ebpf.c)
  -m MODEL, --model MODEL
                        The path to the Lucid model (default: /tmp/model.h5)
  -e EXTRACTOR, --extractor EXTRACTOR
                        The path to the Extractor module (default:
                        /tmp/extract.py)
  -t TIME_WINDOW, --time_window TIME_WINDOW
                        The time window used both for eBPF extraction and NN
                        models (default: 10)
  -x XDP_MODE, --xdp_mode XDP_MODE
                        The XDP mode used (XDP_SKB = 1 << 1, XDP_DRV = 1 << 2,
                        XDP_HW = 1 << 3) (default: 2)
```

This script is executed within the compiled Docker, in order to avoid installing heavy dependencies (BCC) locally.
In order to run the program, type:

```bash
docker run --gpus all --rm --privileged --network host \
        -v /lib/modules:/lib/modules:ro -v /usr/src:/usr/src:ro \
        -v /etc/localtime:/etc/localtime:ro \
        -v /<path_to_project>/probes/toshi/ebpf.c:/tmp/ebpf.c:ro \
        -v /<path_to_project>/probes/toshi/extract.py:/tmp/extract.py:ro \
        s41m0n/adaptive:latest python3 injector.py <interface>
```

The *extract* function is dynamically loaded from a different Python script (in my case [extract.py](extract.py)), as I wanted to have the test phase automatized, meaning that different extractor script have been used, in order to extract different subset of features. The *MODEL* parameter is optional: when provided, the extract script performs also prediction, otherwise it returns all the measured times, including Numpy padding, but not the prediction one.

The eBPF code provided [ebpf.c](ebpf.c) is just an example I used to extract features from traffic in order to detect possible DDoS attacks, but you can use your source code, according to your extract.py script.