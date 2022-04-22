# Developers guide

This section tries to point out most of the best practises and tricks that internat and external developers should know before committing to the main repository.

## Contents

- [1. Coding](#1-coding)
- [2. Documentation](#3-documentation)
- [3. Testing](#3-testing)

## 1. Coding

Many components can be enhanced or created within this framework. The fundamental rules are:

- do not repeat: before submitting a functionality, please make sure that it has not already been included in previous commits;
- to submit new plugins, please make sure they are compliant with the requirements (for example, refer to the [dechainy_plugin_firewall](https://github.com/dechainers/dechainy_plugin_firewall);
- to submit REST functionalities, please refer to the [dechainy_web](https://github.com/dechainers/dechainy_web) repository;
- personalized control plane code is not safe to be executed, thus if you plan to use it in a real scenario please consider all the possible vulnerabilities/exploitations;
- keep the source files as separated as possible, avoiding mixing functionalities that affects different component in the same file.

## 2. Documentation

One of the most important rules is to develop well-documented code, in order to automatically generate the API documentation.
The tool used for the generation is [pdoc3](https://pypi.org/project/pdoc3/), and the format must be *markdown*. However, the CI/CD pipeline updates automatically the documentation whenever needed, thus you do not need to worry.

However, if you want to check everything is as expected, you can locally run:

```bash
pdoc3 dechainy/ -o <dir>
```

The documentation is generated under the *dir* directory. Compiling locally requires the entire framework to be up and running, meaning also all its dependencies. For that reason, I strongly suggest using the [Dockerfile](../Dockerfile.docgen) in order to build a Docker image with all the dependency and ready to generate the doc, or you can use the most updated **s41m0n/dechainy:docgen** one and mount the entire *dechainy/* directory into */app/dechainy*, in order to have the code up-to-date.

```bash
docker build -f Dockerfile.docgen -t s41m0n/dechainy:docgen .
```

```bash
docker run --rm --privileged --network host \
            -v /lib/modules:/lib/modules:ro \
            -v /etc/localtime:/etc/localtime:ro \
            -v /usr/src:/usr/src:ro \
            -v /tmp:/tmp:rw \
            s41m0n/dechainy:$GITHUB_SHA-docgen pdoc3 dechainy/ -o /tmp
```

## 3. Testing

When contributing, it is extremely important to test your implementation. There is a GitHub pipeline for CI/CD which
performs all the specified tests both locally and using the Docker Image.

However, to run them in your device, run:

```bash
sudo pytest
```

There is also a Docker image to avoid installing everything locally:

```bash
docker build --build-arg DEFAULT_BUILDTYPE=test -t s41m0n/dechainy:test .
```

You can then run it typing:

```bash
docker run --rm --privileged --network host \
          -v /lib/modules:/lib/modules:ro \
          -v /etc/localtime:/etc/localtime:ro \
          -v /usr/src:/usr/src:ro \
          s41m0n/dechainy:test bash -c "flake8 . --count --exit-zero --max-line-length=127 --statistics && pytest"
```