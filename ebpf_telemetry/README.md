# EBPF Telemetry POC
This is the beginning of work on a proof-of-concept to generate Linux
telemetry using EBPF.  It is not production ready by any means and is provided
here to permit collaboration and to share developments.

# Build
From the ebpf_telemetry directory:

$ mkdir build
$ cd build
$ cmake ..
$ make

# Run
From the ebpf_telemetry/build directory:

$ cd ebpf_loader
$ sudo ../ebpf_telemetry

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


