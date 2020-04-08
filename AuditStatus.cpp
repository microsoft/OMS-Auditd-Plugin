/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "AuditStatus.h"

#include <cstdint>

int AuditStatus::GetStatus(Netlink& netlink) {
    ::memset(this, 0, sizeof(AuditStatus));

    bool received_response = false;
    auto ret = netlink.Send(AUDIT_GET, nullptr, 0, [this,&received_response](uint16_t type, uint16_t flags, const void* data, size_t len) -> bool {
        if (type == AUDIT_GET) {
            std::memcpy(this, data, std::min(len, sizeof(AuditStatus)));
            received_response = true;
        }
        return true;
    });
    if (ret != 0) {
        return ret;
    }
    if (!received_response) {
        return -ENOMSG;
    }
    return 0;
}

int AuditStatus::UpdateStatus(Netlink& netlink) {
    size_t size = sizeof(AuditStatus);
    if ((_mask & ~static_cast<uint32_t>(FieldMask::V1Status)) == 0) {
        size = offsetof(AuditStatus, _feature_bitmap);
    }

    return netlink.Send(AUDIT_SET, this, size, nullptr);
}
