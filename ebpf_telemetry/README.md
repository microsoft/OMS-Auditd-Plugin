# EBPF Telemetry POC
This is the beginning of work on a proof-of-concept to generate Linux
telemetry using EBPF.  It is provided
here to permit collaboration and to share developments.

This work currently only supports x64.

# Dependencies

- sudo apt update
- sudo apt install gcc g++ make cmake libelf-dev llvm clang

Please note, this project no longer requires kernel sources to build.

# Clone
- git clone https://github.com/microsoft/OMS-Auditd-Plugin.git
- cd OMS-Auditd-Plugin
- git checkout MSTIC-Research
- cd ebpf_telemetry

# Build
From the ebpf_telemetry directory:

- mkdir build
- cd build
- cmake ..
- make

# Configure
From the ebpf_telemetry/build directory:
- cd ../get_offsets
- make
- make conf > ../ebpf_telemetry.conf
- cd ../build

Feel free to edit the rules in syscalls.rules to specify what to log.  Note there are filters
hard-coded into the ebpf_telemetry.c program.

# Run
From the ebpf_telemetry/build directory:

- sudo ./ebpf_telemetry

Use '-s' to send the output to Syslog; '-q' to not send output to screen; and '-Q' to make it super quiet.

# EBPF programs
There are 4 EBPF programs, each targetted at different EBPF capability levels:

- ebpf_telemetry_kern_tp.c - for kernels without raw tracepoints, lower than v4.17
- ebpf_telemetry_kern_raw_tp_sub4096.c - for kernels limited to 4096 instructions, v4.17 to v5.1
- ebpf_telemetry_kern_raw_tp_noloops.c - for kernels that don't permit loops, v5.2
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


