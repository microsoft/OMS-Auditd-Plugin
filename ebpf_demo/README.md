EBPF Demo

This small EBPF program demonstrates how to build a simple tracepoint
program outside of the kernel tree, that doesn't rely on kernel sources.

It builds and runs on kernel v4.14 and above.

* mkdir build
* cd build
* cmake ..
* make
* sudo ./user

Needs cmake>=3.10, clang, llvm and libelf-dev.  It fetches its own copy of
libbpf from github as part of configure and build.


