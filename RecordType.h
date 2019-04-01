/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

/*****************************************************************************
* New record types are in 10000 range to avoid collision with existing codes.
*
* 14688 was chosen for aggregate process creation records, given similarity
* to windows 4688 events.
*
* 11309 was chosen for fragmented EXECVE records, following use of 1309 for
* native AUDIT_EXECVE.
*
******************************************************************************/

#define SYSCALL_RECORD_TYPE 14688
#define FRAGMENT_RECORD_TYPE 11309
#define PROCESS_INVENTORY_RECORD_TYPE 10000
#define SYSCALL_RECORD_NAME "AUOMS_SYSCALL"
#define FRAGMENT_RECORD_NAME "AUOMS_FRAGMENT"
#define PROCESS_INVENTORY_RECORD_NAME "AUOMS_PROCESS_INVENTORY"
#define PROCESS_INVENTORY_RECORD_KEY "oms-inventory"

