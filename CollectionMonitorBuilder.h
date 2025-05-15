/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef __COLLECTION_MONITOR_BUILDER_H__
#define __COLLECTION_MONITOR_BUILDER_H__

#include "ICollectionMonitor.h"
#include <PriorityQueue.h>

#include <memory>

typedef enum {
    COLLECTION_MONITOR_TYPE_UNKNOWN,
    COLLECTION_MONITOR_TYPE_NETLINK,
    COLLECTION_MONITOR_TYPE_AUDITD
} COLLECTION_MONITOR_TYPE;

class CollectionMonitorBuilder {
public:
    static std::shared_ptr<ICollectionMonitor>
    Build(
        const COLLECTION_MONITOR_TYPE& type,
        std::shared_ptr<PriorityQueue> queue,
        const std::string& auditd_path,
        const std::string& collector_path,
        const std::string& collector_config_path
    );

private:
    CollectionMonitorBuilder() = delete;
    CollectionMonitorBuilder(const CollectionMonitorBuilder&) = delete;
    CollectionMonitorBuilder& operator=(
        const CollectionMonitorBuilder&
    ) = delete;
};

#endif /* __COLLECTION_MONITOR_BUILDER_H__ */