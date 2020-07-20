EBPF Perf Output POC

This small EBPF program demonstrates that the perf ring buffer has a sample
max size of 64K and going beyond that causes samples to appear to overlap
in memory (seen in the difference in memory pointers) and cause corruption
of samples.

* mkdir build
* cd build
* cmake ..
* make
* sudo ./user

Needs clang, llvm and libelf-dev.  It fetches its own copy of libbpf from
github as part of configure and build.


