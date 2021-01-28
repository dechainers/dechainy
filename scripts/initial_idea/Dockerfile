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

RUN apt-get update && \
    apt-get -y install pbuilder aptitude && \
    cd /root && \
    git clone https://github.com/iovisor/bcc.git

WORKDIR /root/bcc

RUN /usr/lib/pbuilder/pbuilder-satisfydepends && \
    ./scripts/build-deb.sh release

######################
# Final Docker image #
######################
FROM python:3.8-slim

ARG DEBIAN_FRONTEND=noninteractive

COPY --from=builder /root/bcc/*.deb /root/bcc/
COPY injector.py probes/toshi/* /tmp/
WORKDIR /tmp

RUN \
  apt update -y && \
  apt install -y libncurses5 binutils python python3 libelf1 kmod  && \
  pip3 install dnslib cachetools tensorflow keras && \
  dpkg -i /root/bcc/*.deb && \
  ln -s /usr/lib/python3/dist-packages/bcc /usr/local/lib/python3.8/site-packages/bcc && \
  rm -rf /root/bcc && \
  apt clean && \
  apt autoremove

CMD exec python injector.py lo

#####################
# docker run --gpus all --rm --privileged --network host \
#        -v /lib/modules:/lib/modules:ro -v /usr/src:/usr/src:ro \
#        -v /etc/localtime:/etc/localtime:ro \
#        s41m0n/adaptive:latest python3 injector.py wlp59s0
#
# You can mount volumes as you want, to change also the ebpf.c and extract.py
#####################