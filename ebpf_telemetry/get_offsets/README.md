# EBPF Telemetry POC get_offsets
This is the beginning of work on a proof-of-concept to generate Linux
telemetry using EBPF.  It is not production ready by any means and is provided
here to permit collaboration and to share developments.

get_offsets is a kernel module that obtains the offsets into kernel internals
and generates content for a ebpf_telemetry.conf file.  This file is required
for ebpf_telemetry to be able to access kernel structs.

# Dependencies
- sudo apt install make gcc

# Build
From the ebpf_telemetry/get_offsets *on the target machine* directory:

- make

# Run
From the ebpf_telemetry/get_offsets *on the target machine* directory:

- make run

# Generate config file
From the ebpf_telemetry/get_offsets *on the target machine* directory:

- make run | grep '^\[' | tail -n +3 | head -n -2 | cut -d' ' -f2- > ../ebpf_telemetry.conf
or
- make conf > ../ebpf_telemetry.conf

# mount.h
get_offsets includes mount.h taken verbatim from the source of v4.15 of the Linux kernel.
This file can often be found at /usr/src/linux/fs/mount.h.
This source file hasn't materially changed (at least in relation to the struct mount that
we require) between v4.0 and v5.8 of the Linux kernel.  Post v5.8, if the definition of
struct mount changes, the source file get_offsets.c can be simply modified to pick up the
version in the Linux source - this will require the source code.  Alternatively, a suitable
version of this file can be extracted from the relevant archive of the kernel source and
placed in the ebpf_telemetry/get_offsets directory.

# Licenses
get_offsets is licensed under GPL2.
get_offsets includes mount.h taken verbatim from the source of v4.15 of the Linux kernel;
this file is licensed under GPL2.

# Support
No support is provided.

# Feedback
Feel free to submit PRs to the MSTIC-Research branch - this project doesn't
exist in the master branch.

Feel free to contact kevin.sheldrake [AT] microsoft.com to provide feedback or
ask questions.


