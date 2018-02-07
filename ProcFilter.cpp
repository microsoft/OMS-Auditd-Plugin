/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "ProcFilter.h"

#include "Queue.h"
#include "Logger.h"

#include <stdexcept>
#include <cassert>
#include <cctype>
#include <cstring>

#include <string>
#include <sstream>
#include <vector>
#include <unordered_map>
#include <iostream>
#include <system_error>

#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/filereadstream.h>

// This include file can only be included in ONE translation unit
#include <auparse.h>

#define MAX_ITERATION_DEPTH 10

extern "C" {
#include <dlfcn.h>
}

/*****************************************************************************
 * Dynamicly load needed libaudit symbols
 *
 * There are two version of libaudit (libaudit0, and libaudit1) this makes it
 * impossible to build once then run on all supported distro versions.
 *
 * But, since libauparse is available on all supported distros, and it also
 * links to libaudit, all we need to do is call dlsym to get the function
 * pointer(s) we need.
 *
 *****************************************************************************/



/*****************************************************************************
 ** ProcFilter
 *****************************************************************************/

ProcFilter* ProcFilter::_instance = NULL;

set<string> ProcFilter::_blocked_process_names;

void ProcFilter::static_init()
{
    _blocked_process_names.insert("waagent");
    _blocked_process_names.insert("omsconfig");
    _blocked_process_names.insert("omsagent");

}

list<ProcessInfo>* ProcFilter::get_all_processes()
{
    list<ProcessInfo>* list = new list<ProcessInfo>();

    // TODO: implement

    return list;
}
void ProcFilter::compile_proc_list(list<ProcessInfo>* allProcs)
{
        // add root blocking processes
        for (const ProcessInfo& proc : allProcs)
        {
            for (const string& blockedName : ProcFilter::_blocked_process_names)
            {
                if (proc.name.find(blockedName) != std::string::npos)
                {
                    _proc_list.insert(proc.pid);
                }
            }
        }

        // find child blocked processes with limited depth of search
        bool newProcFound;
        int depth = 0;
        do {
            newProcFound = false;
            ++depth;
            for (const ProcessInfo& proc : allProcs)
            {
                newProcFound = newProcFound | AddProcess(proc.pid, proc.ppid);
            }

        } while (newProcfound && (depth < MAX_ITERATION_DEPTH)

}

ProcFilter* ProcFilter::GetInstance()
{
    if (_instance == NULL)
    {
        _instance = new ProcFilter();
    }

    return _instance;
}

ProcFilter::~ProcFilter()
{
}

void ProcFilter::Initialize()
{
    _proc_list.clear();
    // TODO: scan existing processes and choose those in the names list and children
    list<ProcessInfo>* list = get_all_processes();
    compile_proc_list(list);
    delete list;
}

ProcFilter::ProcFilter()
{
    Initialize();
}

bool ProcFilter::ShouldBlock(int pid)
{
    return (_proc_list.find(pid) != _proc_list.end());
}

bool ProcFilter::AddProcess(int pid, int ppid)
{
    if(_proc_list.find(ppid) != _proc_list.end())
    {
        _proc_list.insert(pid);
        return true;
    }
    return false;
}
