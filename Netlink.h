//
// Created by tad on 2/7/19.
//

#ifndef AUOMS_NETLINK_H
#define AUOMS_NETLINK_H

#include <functional>
#include <future>

#include <linux/netlink.h>
#include <linux/audit.h>
#include "RunBase.h"

class Netlink: private RunBase {
public:
    static constexpr int SUCCESS = 1;
    static constexpr int TIMEOUT = 0;
    static constexpr int CLOSED = -1;
    static constexpr int FAILED = -2;
    typedef std::function<bool(uint16_t type, uint16_t flags, void* data, size_t len)> reply_fn_t;

    Netlink(): _fd(-1), _sequence(1),_default_msg_handler_fn(nullptr) {}

    bool Open(reply_fn_t default_msg_handler_fn);
    void Close();

    // Return 1 on success, 0 on timeout, -1 on closed, -2 on failure, throw exception if fn threw an exception
    int Send(uint16_t type, uint16_t flags, void* data, size_t len, reply_fn_t reply_fn);

    // Return 1 on success, 0 on timeout, -1 on closed, -2 on failure
    int AuditGet(audit_status& status);

    // Return 1 on success, 0 on timeout, -1 on closed, -2 on failure
    int AuditSet(audit_status& status);

    int AuditGetPid(uint32_t& pid);
    int AuditSetPid(uint32_t pid);

protected:
    void on_stopping() override;
    void on_stop() override;
    void run() override;

private:

    class ReplyRec {
    public:
        explicit ReplyRec(reply_fn_t fn, uint16_t flags): _req_time(std::chrono::steady_clock::now()), _flags(flags), _done(false), _fn(std::move(fn)) {}
        std::chrono::steady_clock::time_point _req_time;
        uint16_t _flags;
        bool _done;
        reply_fn_t _fn;
        std::promise<int> _promise;
    };

    void flush_replies(bool is_exit);

    int _fd;
    uint32_t _sequence;
    std::thread _thread;
    reply_fn_t _default_msg_handler_fn;
    std::unordered_map<uint32_t, ReplyRec> _replies;
    std::array<uint8_t, 9*1024> _data;
};


#endif //AUOMS_NETLINK_H
