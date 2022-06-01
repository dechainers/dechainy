# Installation

## Requirements

The project comes with a quick and easy to build Docker image, which can be built and used in less than a minute.
Although, for those who does not want to use the image and run the module locally, the requirements are:

* requirements.txt
* python3-pytest (only if testing)
* BCC (read following lines)

Despite existing a *python3-bpfcc* packet from the Ubuntu package manager *apt*, it is not the latest release of such tool. Thus, many of the advanced
operations with eBPF maps are not possible, and the framework would fail starting due to an import error. I strongly suggest downloading the latest
code from their [GitHub page](https://github.com/iovisor/bcc) and compile it as follows.

## Install

The usage of the Docker images is strongly recommended, to avoid installing the entire BCC dependency locally.

### Local

```bash
# Installing BCC
git clone https://github.com/iovisor/bcc.git
cd bcc
sudo /usr/lib/pbuilder/pbuilder-satisfydepends
sudo ./scripts/build-deb.sh release
sudo dpkg -i *.deb
cd .. 

# Installing other dependencies
sudo apt install python3-pytest
sudo pip3 install -r requirements.txt
sudo python3 -m dechainy
```

If you want to install DeChainy as a Python package, after satisfying the BCC dependency, you can use the [setup.py](../setup.py) script:

```bash
sudo python3 setup.py install
```

From now on, you can reference to this framework as you would do for any other Python package, like *import numpy*.

### Docker

```bash
docker build -f Dockerfile -t s41m0n/dechainy:latest .
```

```bash
docker run --rm --privileged --network host \
    -v /lib/modules:/lib/modules:ro \
    -v /etc/localtime:/etc/localtime:ro \
    -v /usr/src:/usr/src:ro \
    -v $(pwd)/dechainy:/app/:ro \ # you can mount at runtime the new code you develop, instead of rebuilding it
    -v $(pwd)/startup.json:/app/startup.json:ro \ # or you can just mount only the startup configuration
    s41m0n/dechainy:latest
```

If you are willing to use TensorFlow or Keras (using only CPU support by now), the main [Dockerfile](../Dockerfile) accepts an additional
parameter to include such additional packages:

```bash
docker build --build-arg DEFAULT_BUILDTYPE=ml -t s41m0n/dechainy:ml .
```
