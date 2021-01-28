# F.A.Q.

This section contains some useful answer to the most common questions. For more info, do not forget to check also
the [BCC F.A.Q](https://github.com/iovisor/bcc/blob/master/FAQ.txt), in case the issue is related to the compilation of your eBPF code.

**[Q] - Why not using GiHub actions for the docs instead of readthedocs?**

[A] - As you may see, there is a [config.yml](_config.yml) file, but since also my personal website is published under GitHub Pages ([here](https://s41m0n.github.io)) the *search* bar of the generated DeChainy website would fail, looking into the root domain instead of in the project subfolder.

**[Q] - Why the Release workflow uses custom run command instead of [this](https://github.com/marketplace/actions/build-and-push-docker-images)?**

[A] - Since I want to use Docker cache, to improve build time, I cannot use that automated script, as it would imply a compilation from the beginning (entire BCC) for all the different images.