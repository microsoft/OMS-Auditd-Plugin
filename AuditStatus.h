/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_AUDITSTATUS_H
#define AUOMS_AUDITSTATUS_H

#include "Netlink.h"

class AuditStatus {
public:
    enum class FieldMask: uint32_t {
        Enabled         = 0x0001, // AUDIT_STATUS_ENABLED
        Failure         = 0x0002, // AUDIT_STATUS_FAILURE
        Pid             = 0x0004, // AUDIT_STATUS_PID
        RateLimit       = 0x0008, // AUDIT_STATUS_RATE_LIMIT
        BacklogLimit    = 0x0010, // AUDIT_STATUS_BACKLOG_LIMIT
        BacklogWaitTime = 0x0020, // AUDIT_STATUS_BACKLOG_WAIT_TIME
        Lost            = 0x0040, // AUDIT_STATUS_LOST
        V1Status        = 0x001F, // Only fields available in old kernels (e.g. < 3.12.0)
    };

    enum class Feature: uint32_t {
        BacklogLimit    = 0x00000001, // AUDIT_FEATURE_BITMAP_BACKLOG_LIMIT
        BacklogWaitTime = 0x00000002, // AUDIT_FEATURE_BITMAP_BACKLOG_WAIT_TIME
        ExecutablePath  = 0x00000004, // AUDIT_FEATURE_BITMAP_EXECUTABLE_PATH
        ExcludeExtend   = 0x00000008, // AUDIT_FEATURE_BITMAP_EXCLUDE_EXTEND
        SessionidFilter = 0x00000010, // AUDIT_FEATURE_BITMAP_SESSIONID_FILTER
        LostReset       = 0x00000020, // AUDIT_FEATURE_BITMAP_LOST_RESET
        FilterFs        = 0x00000040, // AUDIT_FEATURE_BITMAP_FILTER_FS
    };

    AuditStatus() {
        ::memset(this, 0, sizeof(AuditStatus));
    }

    inline bool HasFeature(Feature feature) {
        if (feature == Feature::BacklogLimit) {
            return _feature_bitmap == 0 || (_feature_bitmap & static_cast<uint32_t>(Feature::BacklogLimit)) != 0;
        } else {
            return (_feature_bitmap & static_cast<uint32_t>(feature)) != 0;
        }
    }

    uint32_t GetEnabled()         { return _enabled; }
    uint32_t GetFailure()         { return _failure; }
    uint32_t GetPid()             { return _pid; }
    uint32_t GetRateLimit()       { return _rate_limit; }
    uint32_t GetBacklogLimit()    { return _backlog_limit; }
    uint32_t GetLost()            { return _lost; }
    uint32_t GetBacklog()         { return _backlog; }
    uint32_t GetBacklogWaitTime() { return _backlog_wait_time; }

    void SetEnabled(uint32_t value) {
        _mask |= static_cast<uint32_t>(FieldMask::Enabled);
        _enabled = value;
    }

    void SetFailure(uint32_t value)  {
        _mask |= static_cast<uint32_t>(FieldMask::Failure);
        _failure = value;
    }

    void SetPid(uint32_t value)  {
        _mask |= static_cast<uint32_t>(FieldMask::Pid);
        _pid = value;
    }

    void SetRateLimit(uint32_t value)  {
        _mask |= static_cast<uint32_t>(FieldMask::RateLimit);
        _rate_limit = value;
    }

    void SetBacklogLimit(uint32_t value)  {
        _mask |= static_cast<uint32_t>(FieldMask::BacklogLimit);
        _backlog_limit = value;
    }

    void SetBacklogWaitTime(uint32_t value)  {
        _mask |= static_cast<uint32_t>(FieldMask::BacklogWaitTime);
        _backlog_wait_time = value;
    }

    void SetLost(uint32_t value)  {
        _mask |= static_cast<uint32_t>(FieldMask::Lost);
        _lost = value;
    }

    int GetStatus(Netlink& netlink);
    int UpdateStatus(Netlink& netlink);

private:
    // These fields mirror the struct audit_status fields defined in /usr/include/linux/audit.h
    // DO NOT ADD OR REMOVE ANY FIELDS IN THE CLASS (except to mirror struct audit_status fields defined in /usr/include/linux/audit.h)
    uint32_t  _mask;
    uint32_t  _enabled;
    uint32_t  _failure;
    uint32_t  _pid;
    uint32_t  _rate_limit;
    uint32_t  _backlog_limit;
    uint32_t  _lost;
    uint32_t  _backlog;
    uint32_t  _feature_bitmap;
    uint32_t  _backlog_wait_time;
};


#endif //AUOMS_AUDITSTATUS_H
