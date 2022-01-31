# F.A.Q

This section contains some useful answer to the most common questions. For more info, do not forget to check also
the [BCC F.A.Q](https://github.com/iovisor/bcc/blob/master/FAQ.txt), in case the issue is related to the compilation of your eBPF code.

**[Q] - Why the Release workflow uses custom run command instead of [this](https://github.com/marketplace/actions/build-and-push-docker-images)?**

[A] - Since I want to use Docker cache, to improve build time, I cannot use that automated script, as it would imply a compilation from the beginning (entire BCC) for all the different images.
