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

class ReplyRec;

class Netlink: private RunBase {
public:
    typedef std::function<bool(uint16_t type, uint16_t flags, const void* data, size_t len)> reply_fn_t;

    Netlink(): _fd(-1), _sequence(1), _default_msg_handler_fn(), _quite(false), _known_seq(), _replies(), _data() {}

    void SetQuite() { _quite = true; }

    /*
     * Methods return 0 on success and < 0 on failure.
     * If the Netlink is closed prior to call, then will return -ENOTCONN
     * If Netlink is closed after call, but before reply, will return -ECANCELED
     * If reply does not arrive before timeout, will retuen -ETIMEDOUT
     * If reply is NLMSG_ERROR, will return nlmsgerr->error (which is already negative)
     * If request fails for another reason will return -errno
     */

    int Open(reply_fn_t&& default_msg_handler_fn, bool multicast = false);
    void Close();

    int Send(uint16_t type, const void* data, size_t len, reply_fn_t&& reply_fn);

    // Will return -ENOMSG if no AUDIT_GET message received
    int AuditGet(audit_status& status);

    int AuditSet(audit_status& status);

    // Will return -ENOMSG if no AUDIT_GET message received
    int AuditGetPid(uint32_t& pid);

    int AuditSetPid(uint32_t pid);

    // Will return -ENOMSG if no AUDIT_GET message received
    int AuditGetEnabled(uint32_t& enabled);

    int AuditSetEnabled(uint32_t enabled);

    int AuditListRules(std::vector<AuditRule>& rules);

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
        explicit ReplyRec(reply_fn_t&& fn): _req_age(std::chrono::steady_clock::now()), _done(false), _fn(std::move(fn)), _promise() {}
        ReplyRec(const ReplyRec& other) = delete;
        ReplyRec(ReplyRec&& other) = delete;
        ReplyRec& operator=(const ReplyRec& other) = delete;
        ReplyRec& operator=(ReplyRec&& other) = delete;

        std::chrono::steady_clock::time_point _req_age;
        bool _done;
        reply_fn_t _fn;
        std::promise<int> _promise;
    };

    void flush_replies(bool is_exit);
    void handle_msg(uint16_t msg_type, uint16_t msg_flags, uint32_t msg_seq, const void* payload_data, size_t payload_len);

    int _fd;
    uint32_t _pid;
    volatile uint32_t _sequence;
    reply_fn_t _default_msg_handler_fn;
    bool _quite;
    std::unordered_map<uint32_t, std::chrono::steady_clock::time_point> _known_seq;
    std::unordered_map<uint32_t, std::shared_ptr<ReplyRec>> _replies;
    std::array<uint8_t, 16*1024> _data;
};

int NetlinkRetry(const std::function<int()>& fn);

#endif //AUOMS_NETLINK_H
