/*
    EBPF Demo

    Copyright (c) Microsoft Corporation

    All rights reserved.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#ifndef EVENT_DEFS_H
#define EVENT_DEFS_H

#include <linux/limits.h>

#define VERSION 1
#define CODE_BYTES 0xdeadbeef

// Event structure
typedef struct e_rec {
    unsigned long int  code_bytes_start; //Always 0xdeadbeef = 3735928559
    unsigned int       version;
    unsigned long long syscall_id;
    unsigned int       pid;
    long long int      return_code;
    char               path[32];
    void               *path_ptr;
    unsigned long int  code_bytes_end; //Always 0xdeadbeef = 3735928559
} event_s;

#endif
