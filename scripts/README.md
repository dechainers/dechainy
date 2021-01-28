# Scripts

This folder contains useful scripts both for users and developers.

* [initial_idea](initial_idea): this folder contains the initial idea of the framework, when I created an apposite injector script with the program SWAP feature enabled, in order to perform measurements of a single probe. From that moment on, I realized I could create something bigger, to provide multiple eBPF programs chain.
* [formatter.py](formatter.py): this scripts is used to format source C, Python and binary files into strings that can be easily inserted into the JSON file of a probe which accepts such fields (e.g., Adaptmon). While source code can be easily converted into an escaped string, a binary files is encoded in base64 (remind to decode it in order to use it).
