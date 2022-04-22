# Copyright 2022 DeChainy
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
import setuptools

from dechainy import project_url, version


with open("README.md", "r") as fh:
    long_description = fh.read()

with open('requirements.txt') as fh:
    requirements = fh.read().splitlines()

setuptools.setup(
    name="dechainy",
    author="Simone Magnani",
    author_email="simonemagnani.96@gmail.com",
    version=version,
    description="An open source framework to easily build and deploy eBPF/XDP network monitoring probes and clusters",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url=project_url,
    packages=setuptools.find_packages(exclude=("tests",)),
    license_files=("LICENSE",),
    classifiers=[
                "Intended Audience :: Developers",
                "License :: OSI Approved :: Apache Software License",
                "Natural Language :: English",
                "Programming Language :: Python :: 3.6"
    ],
    install_requires=requirements,
    include_package_data=True,
    python_requires='>=3.6'
)
