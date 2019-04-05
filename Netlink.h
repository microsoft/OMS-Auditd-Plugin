/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_NETLINK_H
#define AUOMS_NETLINK_H

#include <functional>
#include <future>

#include <linux/netlink.h>
#include <linux/audit.h>
#include "RunBase.h"
#include "AuditRules.h"

class Netlink: private RunBase {
public:
    typedef std::function<bool(uint16_t type, uint16_t flags, const void* data, size_t len)> reply_fn_t;

    Netlink(): _fd(-1), _sequence(1),_default_msg_handler_fn(nullptr), quite(false), _replies(), _data() {}

    void SetQuite() { quite = true; }

    /*
     * Methods return 0 on success and < 0 on failure.
     * If the Netlink is closed prior to call, then will return -ENOTCONN
     * If Netlink is closed after call, but before reply, will return -ECANCELED
     * If reply does not arrive before timeout, will retuen -ETIMEDOUT
     * If reply is NLMSG_ERROR, will return nlmsgerr->error (which is already negative)
     * If request failes for another reason will return -errno
     */

    int Open(reply_fn_t default_msg_handler_fn);
    void Close();

    int Send(uint16_t type, const void* data, size_t len, reply_fn_t reply_fn);

    int AuditGet(audit_status& status);
    int AuditSet(audit_status& status);

    int AuditGetPid(uint32_t& pid);
    int AuditSetPid(uint32_t pid);

    int AuditGetEnabled(uint32_t& enabled);
    int AuditSetEnabled(uint32_t enabled);

    int AuditListRules(std::vector<AuditRule>& rules) {
        return Send(AUDIT_LIST_RULES, nullptr, 0, [&rules](uint16_t type, uint16_t flags, const void* data, size_t len) -> bool {
            if (type == AUDIT_LIST_RULES) {
                rules.emplace_back(data, len);
            }
            return true;
        });
    }

    int AuditAddRule(const AuditRule& rule) {
        if (!rule.IsValid()) {
            throw std::runtime_error("Invalid rule");
        }
        return Send(AUDIT_ADD_RULE, rule.Data(), rule.Size(), nullptr);
    }

    int AuditDelRule(const AuditRule& rule) {
        return Send(AUDIT_DEL_RULE, rule.Data(), rule.Size(), nullptr);
    }

protected:
    void on_stopping() override;
    void on_stop() override;
    void run() override;

private:

    class ReplyRec {
    public:
        explicit ReplyRec(reply_fn_t fn): _req_time(std::chrono::steady_clock::now()), _done(false), _fn(std::move(fn)) {}
        std::chrono::steady_clock::time_point _req_time;
        bool _done;
        reply_fn_t _fn;
        std::promise<int> _promise;
    };

    void flush_replies(bool is_exit);

    int _fd;
    uint32_t _sequence;
    std::thread _thread;
    reply_fn_t _default_msg_handler_fn;
    bool quite;
    std::unordered_map<uint32_t, ReplyRec> _replies;
    std::array<uint8_t, 9*1024> _data;
};


#endif //AUOMS_NETLINK_H
