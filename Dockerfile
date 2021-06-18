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

########################################
# Builder image, to compile latest BCC #
########################################
FROM ubuntu:18.04 as builder

ARG DEBIAN_FRONTEND=noninteractive

RUN apt update && \
    apt install -y pbuilder aptitude && \
    cd /root && \
    git clone https://github.com/iovisor/bcc.git && \
    cd /root/bcc && \
    if [ $(arch) = "aarch64" ]; then \
      apt install -y python python-pip debhelper cmake libllvm9 llvm-9-dev libclang-9-dev clang-format-9 libelf-dev bison flex libfl-dev libedit-dev zlib1g-dev python luajit libluajit-5.1-dev arping iputils-ping iperf netperf ethtool dh-python python3-netaddr python3-pyroute2 python-netaddr && \
      pip install netaddr pyroute2 && \
      pip2 install netaddr pyroute2; \
    else \
      /usr/lib/pbuilder/pbuilder-satisfydepends; \
    fi && \
    ./scripts/build-deb.sh release

######################
# Final Docker image #
######################
FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

# Supported "default", "test" and "ml"
ARG DEFAULT_BUILDTYPE="default"
ENV BUILDTYPE=$DEFAULT_BUILDTYPE

COPY --from=builder /root/bcc/*.deb /root/bcc/
COPY . /app
WORKDIR /app

RUN \
  apt update -y && \
  apt install -y libncurses5 binutils python python3.9 python3-pip libelf1 kmod  && \
  pip3 install dnslib cachetools  && \
  rm -f /usr/bin/python3 && \
  ln -s /usr/bin/python3.9 /usr/bin/python3 && \
  if [ "$BUILDTYPE" = "test" ] ; then       \
    apt install -y python3-pytest &&        \
    pip3 install pytest flake8;              \
  else                                      \
    rm -rf /app/tests;                      \
  fi && \
  if [ "$BUILDTYPE" = "ml" ] ; then \
    if [ $(arch) = "aarch64" ]; then \
      apt install -y python3.9-dev curl build-essential pkg-config libhdf5-dev && \
      curl -sc /tmp/cookie "https://drive.google.com/uc?export=download&id=1EsObTazsUxmIBj-37L3I2hTdXvVItQD8" > /dev/null && \
      CODE="$(awk '/_warning_/ {print $NF}' /tmp/cookie)" && \
      curl -Lb /tmp/cookie "https://drive.google.com/uc?export=download&confirm=${CODE}&id=1EsObTazsUxmIBj-37L3I2hTdXvVItQD8" -o tensorflow-2.5.0-cp39-none-linux_aarch64.whl && \
      pip3 install tensorflow-2.5.0-cp39-none-linux_aarch64.whl && \
      apt remove curl build-essential python3.9-dev; \
    else \
      pip3 install tensorflow; \
    fi\
  fi && \
  dpkg -i /root/bcc/*.deb && \
  pip install -r requirements.txt && \
  rm -rf /root/bcc && \
  apt clean && \
  apt autoremove -y

CMD exec python3 -W ignore -m dechainy

#######################
# docker run --rm -it --privileged --network host -v /lib/modules:/lib/modules:ro \
#   -v /usr/src:/usr/src:ro \
#   -v /etc/localtime:/etc/localtime:ro \
#   s41m0n/dechainy:latest <---------- or dechain:ml-cpu
#
# Could mount every volume, to make the docker access /tmp, or mount the entire DeChainy folder
# to "get" your local updated code, or mount even a NN model for simplicity.
#######################
# To build for arm64 from a non-arm device
#
# docker buildx build -f Dockerfile -t s41m0n/dechainy:arm --platform linux/arm64 . --load 
#######################