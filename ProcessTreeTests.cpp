/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE "ProcessTreeTests"
#include <boost/test/unit_test.hpp>

#include "ProcessTree.h"
#include "Logger.h"
#include "TestEventData.h"
#include "RawEventAccumulator.h"
#include "StringUtils.h"
#include "EventPrioritizer.h"

#include <iostream>

extern "C" {
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
};

void diff_event(int idx, const Event& e, const Event& a) {
    std::stringstream msg;
    if (e.Seconds() != a.Seconds()) {
        msg << "Event["<<idx<<"] Seconds Mismatch: expected " << e.Seconds() << ", got " << a.Seconds();
        throw std::runtime_error(msg.str());
    }
    if (e.Milliseconds() != a.Milliseconds()) {
        msg << "Event["<<idx<<"] Milliseconds Mismatch: expected " << e.Milliseconds() << ", got " << a.Milliseconds();
        throw std::runtime_error(msg.str());
    }
    if (e.Serial() != a.Serial()) {
        msg << "Event["<<idx<<"] Serial Mismatch: expected " << e.Serial() << ", got " << a.Serial();
        throw std::runtime_error(msg.str());
    }
    if (e.Flags() != a.Flags()) {
        msg << "Event["<<idx<<"] Flags Mismatch: expected " << e.Flags() << ", got " << a.Flags();
        throw std::runtime_error(msg.str());
    }
    if (e.Pid() != a.Pid()) {
        msg << "Event["<<idx<<"] Pid Mismatch: expected " << e.Pid() << ", got " << a.Pid();
        throw std::runtime_error(msg.str());
    }

    if (e.NumRecords() != a.NumRecords()) {
        msg << "Event["<<idx<<"] NumRecords Mismatch: expected " << e.NumRecords() << ", got " << a.NumRecords();
        throw std::runtime_error(msg.str());
    }

    for (int r = 0; r < e.NumRecords(); ++r) {
        auto er = e.RecordAt(r);
        auto ar = a.RecordAt(r);

        if (er.RecordType() != ar.RecordType()) {
            msg << "Event["<<idx<<"].Record[" << r << "] RecordType Mismatch: expected " << er.RecordType() << ", got " << ar.RecordType();
            throw std::runtime_error(msg.str());
        }

        if (er.RecordTypeNamePtr() == nullptr || ar.RecordTypeNamePtr() == nullptr) {
            if (er.RecordTypeNamePtr() != ar.RecordTypeNamePtr()) {
                msg << "Event["<<idx<<"].Record[" << r << "] RecordTypeName Mismatch: expected "
                    << (er.RecordTypeNamePtr() == nullptr ? "null" : er.RecordTypeName())
                    << ", got "
                    << (ar.RecordTypeNamePtr() == nullptr ? "null" : ar.RecordTypeName());
                throw std::runtime_error(msg.str());
            }
        } else {
            if (strcmp(er.RecordTypeNamePtr(), ar.RecordTypeNamePtr()) != 0) {
                msg << "Event["<<idx<<"].Record[" << r << "] RecordTypeName Mismatch: expected " << er.RecordTypeNamePtr() << ", got " << ar.RecordTypeNamePtr();
                throw std::runtime_error(msg.str());
            }
        }

        if (er.RecordTextPtr() == nullptr || ar.RecordTextPtr() == nullptr) {
            if (er.RecordTextPtr() != ar.RecordTextPtr()) {
                msg << "Event["<<idx<<"].Record[" << r << "] RecordText Mismatch: expected "
                    << (er.RecordTextPtr() == nullptr ? "null" : er.RecordTextPtr())
                    << ", got "
                    << (ar.RecordTextPtr() == nullptr ? "null" : ar.RecordTextPtr());
                throw std::runtime_error(msg.str());
            }
        } else {
            if (strcmp(er.RecordTextPtr(), ar.RecordTextPtr()) != 0) {
                msg << "Event["<<idx<<"].Record[" << r << "] RecordText Mismatch: expected " << er.RecordTextPtr() << ", got " << ar.RecordTextPtr();
                throw std::runtime_error(msg.str());
            }
        }

        if (er.NumFields() != ar.NumFields()) {
            msg << "Event["<<idx<<"].Record[" << r << "] NumFields Mismatch: expected " << er.NumFields() << ", got " << ar.NumFields() << "\n";

            std::unordered_set<std::string> _en;
            std::unordered_set<std::string> _an;

            for (auto f : er) {
                _en.emplace(f.FieldNamePtr(), f.FieldNameSize());
            }

            for (auto f : ar) {
                _an.emplace(f.FieldNamePtr(), f.FieldNameSize());
            }

            for (auto name : _en) {
                if (_an.count(name) == 0) {
                    msg << "    Expected Field Name Not Found: " << name << "\n";
                }
            }

            for (auto name : _an) {
                if (_en.count(name) == 0) {
                    msg << "    Unxpected Field Name Found: " << name << "\n";
                }
            }

            throw std::runtime_error(msg.str());
        }

        for (int f = 0; f < er.NumFields(); ++f) {
            auto ef = er.FieldAt(f);
            auto af = ar.FieldAt(f);

            if (ef.FieldNamePtr() == nullptr || af.FieldNamePtr() == nullptr) {
                if (ef.FieldNamePtr() != af.FieldNamePtr()) {
                    msg << "Event["<<idx<<"].Record[" << r << "].Field[" << f << "] FieldName Mismatch: expected "
                        << (ef.FieldNamePtr() == nullptr ? "null" : ef.FieldNamePtr())
                        << ", got "
                        << (af.FieldNamePtr() == nullptr ? "null" : af.FieldNamePtr());
                    throw std::runtime_error(msg.str());
                }
            } else {
                if (strcmp(ef.FieldNamePtr(), af.FieldNamePtr()) != 0) {
                    msg << "Event["<<idx<<"].Record[" << r << "].Field[" << f << "] FieldName Mismatch: expected " << ef.FieldNamePtr() << ", got " << af.FieldNamePtr();
                    throw std::runtime_error(msg.str());
                }
            }

            if (ef.RawValuePtr() == nullptr || af.RawValuePtr() == nullptr) {
                if (ef.RawValuePtr() != af.RawValuePtr()) {
                    msg << "Event["<<idx<<"].Record[" << r << "].Field[" << f << "] RawValue Mismatch: expected "
                        << (ef.RawValuePtr() == nullptr ? "null" : ef.RawValuePtr())
                        << ", got "
                        << (af.RawValuePtr() == nullptr ? "null" : af.RawValuePtr());
                    throw std::runtime_error(msg.str());
                }
            } else {
                if (strcmp(ef.RawValuePtr(), af.RawValuePtr()) != 0) {
                    msg << "Event["<<idx<<"].Record[" << r << "].Field[" << f << "] RawValue Mismatch: expected " << ef.RawValuePtr() << ", got " << af.RawValuePtr();
                    throw std::runtime_error(msg.str());
                }
            }

            if (ef.InterpValuePtr() == nullptr || af.InterpValuePtr() == nullptr) {
                if (ef.InterpValuePtr() != af.InterpValuePtr()) {
                    msg << "Event["<<idx<<"].Record[" << r << "].Field[" << f << "] (Name="<<ef.FieldName()<<") InterpValue Mismatch: expected "
                        << (ef.InterpValuePtr() == nullptr ? "null" : ef.InterpValuePtr())
                        << ", got "
                        << (af.InterpValuePtr() == nullptr ? "null" : af.InterpValuePtr());
                    throw std::runtime_error(msg.str());
                }
            } else {
                if (strcmp(ef.InterpValuePtr(), af.InterpValuePtr()) != 0) {
                    msg << "Event["<<idx<<"].Record[" << r << "].Field[" << f << "] (Name="<<ef.FieldName()<<") InterpValue Mismatch: expected " << ef.InterpValuePtr() << ", got " << af.InterpValuePtr();
                    throw std::runtime_error(msg.str());
                }
            }

            if (ef.FieldType() != af.FieldType()) {
                msg << "Event["<<idx<<"].Record[" << r << "].Field[" << f << "] (Name="<<ef.FieldName()<<") FieldType Mismatch: expected " << static_cast<uint>(ef.FieldType()) << ", got " << static_cast<uint>(af.FieldType());
                throw std::runtime_error(msg.str());
            }
        }
    }
}

BOOST_AUTO_TEST_CASE( basic_test ) {
    std::shared_ptr<ProcessTree> _processTree;
    const std::string containerid = "ebe83cd204c5";

    const std::string exe1 = "/containerd-shim";
    const std::string exe2 = "/containerd-shim-runc-v2";

    const std::string cmdline1 = "containerdshim -namespace moby -workdir /var/lib/containerd/io.containerd.runtime.v1.linux/moby/ebe83cd204c57dc745ce21b595e6aaabf805dc4046024e8eacb84633d2461ec1 -address /run/containerd/containerd.sock -containerd-binary /usr/bin/containerd -runtime-root /var/run/docker/runtime-runc";
    const std::string cmdline2 = "/usr/bin/containerd-shim-runc-v2 -namespace moby -id    ebe83cd204c57dc745ce21b595e6aaabf805dc4046024e8eacb84633d2461ec1    -address /run/containerd/containerd.sock";

    auto res = _processTree->ExtractContainerId(exe1, cmdline1);
    BOOST_REQUIRE_EQUAL(res, containerid);
    res = _processTree->ExtractContainerId(exe2, cmdline2);
    BOOST_REQUIRE_EQUAL(res, containerid);
}
