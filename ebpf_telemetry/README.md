# EBPF Telemetry POC
This is the beginning of work on a proof-of-concept to generate Linux
telemetry using EBPF.  It is not production ready by any means and is provided
here to permit collaboration and to share developments.

# Build
From the ebpf_telemetry directory:

- mkdir build
- cd build
- cmake ..
- make

# Run
From the ebpf_telemetry/build directory:

- sudo ./ebpf_telemetry

# EBPF programs
There are 4 EBPF programs, each targetted at different EBPF capability levels:

- ebpf_telemetry_kern_tp.c - for kernels without raw tracepoints, lower than v4.17
- ebpf_telemetry_kern_raw_tp_sub4096.c - for kernels limited to 4096 instructions, v4.17 to v5.0
- ebpf_telemetry_kern_raw_tp_noloops.c - for kernels that don't permit loops, v5.1 to v5.2
- ebpf_telemetry_kern_raw_tp.c - for kernels that permit loops, v5.3 onwards

You can dump the EBPF assembler to reveal the number of instructions in a program with:

llvm-objdump -S -no-show-raw-insn EBPF_OBJECT_FILE.o

# Licenses
The main executable, ebpf_telemetry, is licensed under MIT.
The ebpf_loader shared library is licensed under LGPL2.1.
The ebpf kernel objects are licensed under GPL2.

# Support
No support is provided.

# Feedback
Feel free to submit PRs to the MSTIC-Research branch - this project doesn't
exist in the master branch.

Feel free to contact kevin.sheldrake [AT] microsoft.com to provide feedback or
ask questions.


