#
#
#    microsoft-oms-auditd-plugin
#
#    Copyright (c) Microsoft Corporation
#
#    All rights reserved.
#
#    This library is free software; you can redistribute it and/or
#    modify it under the terms of the GNU Lesser General Public
#    License as published by the Free Software Foundation; either
#    version 2.1 of the License, or (at your option) any later version.
#
#    This library is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#    Lesser General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public
#    License along with this library; if not, write to the Free Software
#    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#


#################################################################################
# NOTE:                                                                         #
# Due to the clever way that the EBPF programs are built, any modifications to  #
# this file can upset the CMake cache and cause upredictable building errors.   #
# To avoid this, firstly always build in a build directory, e.g.:               #
#                                                                               #
#    $ mkdir build; cd build                                                    #
#    $ cmake ..                                                                 #
#    $ make                                                                     #
#                                                                               #
# and subsequently, if the CMake cache does get upset, simply remove the build  #
# directory and start again with a fresh build directory, e.g.:                 #
#                                                                               #
#    $ cd ..                                                                    #
#    $ rm -rf build                                                             #
#    $ mkdir build; cd build                                                    #
#    $ cmake ..  <-DDEBUG_K=On> : to print out kernel debugging to trace_pipe   #
#    $ make                                                                     #
#                                                                               #
#################################################################################
# TIP:                                                                          #
# If this CMake file stops working, it could be because you're using a newer    #
# kernel source and the include files have moved. A simple way of finding the   #
# correct list of include directories is to modify the Makefiles in the kernel  #
# source in ${LINUX_SRC}/samples/bpf and ${LINUX_SRC}/tools/lib/bpf and add the #
# -v switch to the compiler. This will cause it to output all the switches it   #
# was called with, plus all the directories it will search for headers.         #
#################################################################################


cmake_minimum_required(VERSION 3.10)

# set the project name
project(EBPF_Loader VERSION 0.1)

# set linux source tree directory (must already have 'make && make headers_install')
set(LINUX_SRC "/usr/src/linux")

include(ExternalProject)

#Set option for Debug Outputs for eBPF programs
option(DEBUG_K "Enter debug mode" Off)

#Fetch libbpf
ExternalProject_Add(libbpf
    GIT_REPOSITORY https://github.com/libbpf/libbpf.git
    GIT_TAG master
    PREFIX ./libbpf
    CONFIGURE_COMMAND ""
    BUILD_COMMAND cd ../libbpf/src && bash -c "CFLAGS=\"-g -O2 -Werror -Wall -fPIC\" make"
    INSTALL_COMMAND ""
    )

set(libbpf_SOURCE_DIR ${CMAKE_BINARY_DIR}/ebpf_loader/libbpf/src/libbpf)

# make ebpf_loader
add_library(ebpf_loader SHARED ebpf_telemetry_loader.c)
add_definitions("-fPIC")
add_dependencies(ebpf_loader libbpf)
target_link_libraries(ebpf_loader ${libbpf_SOURCE_DIR}/src/libbpf.a elf z)

if (STOPLOOP)
    message("setting STOPLOOP Count=${STOPLOOP}")
    target_compile_definitions( ebpf_loader PUBLIC STOPLOOP=${STOPLOOP})
endif()

target_include_directories(ebpf_loader PUBLIC
                           "${PROJECT_BINARY_DIR}"
                           "${libbpf_SOURCE_DIR}/src"
                           "${libbpf_SOURCE_DIR}/include"
                           "${libbpf_SOURCE_DIR}/include/asm"
                           "${libbpf_SOURCE_DIR}/include/linux"
                           "${libbpf_SOURCE_DIR}/include/tools"
                           "${libbpf_SOURCE_DIR}/include/uapi"
                           "${libbpf_SOURCE_DIR}/include/uapi/linux"
                           "${LINUX_SRC}/tools/lib"
                           "${LINUX_SRC}/tools/perf"
                           "${LINUX_SRC}/tools/include"
                           "${LINUX_SRC}/tools/arch/x86/include/uapi"
                           "${LINUX_SRC}/tools/include/uapi"
                           "${LINUX_SRC}/arch/x86/include/uapi"
                           "${LINUX_SRC}/arch/x86/include/generated/uapi"
                           "${LINUX_SRC}/include/uapi"
                           "${LINUX_SRC}/include"
                           "${LINUX_SRC}/include/x86_64-linux-gnu/"
                           "${LINUX_SRC}/include/generated/uapi"
                           "/usr/include"
                           )

# list of ebpf programs to make
set(EBPF_PROGS
#               ebpf_telemetry_kern_tp 
               ebpf_telemetry_kern_raw_tp
)

#################################################################################
# Everything below this point should be fairly static.  Ensure LINUX_SRC points #
# to the correct directory for the kernel sources; otherwise, leave it alone    #
# unless things start breaking. :)                                              #
#################################################################################


#
# EBPF COMPILE OPTIONS
#
# This section specifies the options for building ebpf programs
#

# set binaries and options for clang and llc
set(CLANG "clang")
set(LLC "llc")
set(CLANG_OPTIONS -Wno-unused-value
                  -Wno-pointer-sign
                  -Wno-compare-distinct-pointer-types
                  -Wno-gnu-variable-sized-type-not-at-end
                  -Wno-address-of-packed-member
                  -Wno-tautological-compare
                  -Wno-unknown-warning-option
                  )
set(CLANG_DEFINES -D __KERNEL__
                  -D __BPF_TRACING__
                  -D __TARGET_ARCH_x86
                  )
if (DEBUG_K)
    message("Using DEBUG_K Option...")
    list(APPEND CLANG_DEFINES -DDEBUG_K)
endif()

set(CLANG_INCLUDES -include "${LINUX_SRC}/include/linux/kconfig.h"
                   -include "${LINUX_SRC}/samples/bpf/asm_goto_workaround.h"
                   -I "${libbpf_SOURCE_DIR}/src"
                   -I "${LINUX_SRC}/arch/x86/include"
                   -I "${LINUX_SRC}/arch/x86/include/generated"
                   -I "${LINUX_SRC}/include"
                   -I "${LINUX_SRC}/arch/x86/include/uapi"
                   -I "${LINUX_SRC}/arch/x86/include/generated/uapi"
                   -I "${LINUX_SRC}/include/uapi"
                   -I "${LINUX_SRC}/include/generated/uapi"
                   -I "${LINUX_SRC}/ubuntu/include"
                   -I "${LINUX_SRC}/samples/bpf"
                   -I "${LINUX_SRC}/tools/testing/selftests/bpf/"
                   )

#
# EBPF
#
# This section makes the EBPF programs
#

# function to make ebpf programs
function(build_ebpf ebpfsrc)
    add_custom_command(OUTPUT ${ebpfsrc}.o
                       COMMAND "${CLANG}" -nostdinc -isystem `gcc -print-file-name=include` ${CLANG_INCLUDES} ${CLANG_DEFINES} -O2 ${CLANG_OPTIONS} -emit-llvm -c "${CMAKE_SOURCE_DIR}/ebpf_loader/ebpf_kern/${ebpfsrc}.c" -o -| "${LLC}" -march=bpf -filetype=obj -o "${ebpfsrc}.o"
                       COMMENT "Building EBPF object ${ebpfsrc}.o"
                       DEPENDS ebpf_kern/${ebpfsrc}.c
                       DEPENDS libbpf
                       DEPENDS ../event_defs.h
                       DEPENDS ebpf_kern/ebpf_kern_common.h
                       )
endfunction()

# loop for all ebpf programs
foreach(EBPF_PROG IN LISTS EBPF_PROGS)
    
    # add custom target to build all ebpf programs with 'all'
    add_custom_target(${EBPF_PROG} ALL
                      DEPENDS ${EBPF_PROG}.o
                      )

    # test to only build ebpf programs when they have changed
    if(${CMAKE_SOURCE_DIR}/ebpf_loader/ebpf_kern/${EBPF_PROG}.c IS_NEWER_THAN ${CMAKE_BINARY_DIR}/${EBPF_PROG}.o)
        build_ebpf(${EBPF_PROG})
    endif()

    # add ebpf programs to clean
    set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES ${EBPF_PROG}.o)
endforeach(EBPF_PROG)


