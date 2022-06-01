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
FROM s41m0n/bcc:latest

ARG DEBIAN_FRONTEND=noninteractive

# Supported "default", "docgen", "test", "ml"
ARG DEFAULT_BUILDTYPE="default"
ENV BUILDTYPE=$DEFAULT_BUILDTYPE

COPY . /app
WORKDIR /app

RUN if [ "$BUILDTYPE" = "test" ] ; then       \
      pip install pytest flake8;              \
    else                                      \
      rm -rf /app/tests;                      \
    fi

RUN if [ "$BUILDTYPE" = "ml" ] ; then \
      if [ $(arch) = "aarch64" ]; then \
        apt update && apt install -y python3.9-dev curl build-essential pkg-config libhdf5-dev && \
        curl -sc /tmp/cookie "https://drive.google.com/uc?export=download&id=1EsObTazsUxmIBj-37L3I2hTdXvVItQD8" > /dev/null && \
        CODE="$(awk '/_warning_/ {print $NF}' /tmp/cookie)" && \
        curl -Lb /tmp/cookie "https://drive.google.com/uc?export=download&confirm=${CODE}&id=1EsObTazsUxmIBj-37L3I2hTdXvVItQD8" -o tensorflow-2.5.0-cp39-none-linux_aarch64.whl && \
        pip install tensorflow-2.5.0-cp39-none-linux_aarch64.whl && \
        apt remove curl build-essential python3.9-dev &&\
        apt clean && apt autoremove -y; \
      else \
        pip3 install tensorflow; \
      fi\
    fi &&\
    pip install -r requirements.txt

RUN if [ "$BUILDTYPE" = "docgen" ] ; then \
      pip install pdoc3;\
    fi

CMD ["python3", "-W ignore"]

#######################
# docker run --rm -it --privileged --network host
#   -v /lib/modules:/lib/modules:ro \
#   -v /usr/src:/usr/src:ro \
#   -v /etc/localtime:/etc/localtime:ro 
#   s41m0n/dechainy:<tag> <your_python_code>
#######################
# To build for arm64 from a non-arm device
#
# docker buildx build -f Dockerfile -t s41m0n/dechainy:arm --platform linux/arm64 . --load 
#######################