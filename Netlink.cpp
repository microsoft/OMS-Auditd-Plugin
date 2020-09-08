/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "Netlink.h"
#include "Logger.h"
#include "Retry.h"

#include <sys/socket.h>
#include <linux/netlink.h>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

#ifndef SOL_NETLINIK
// This isn't defined in older socket.h include files.
#define SOL_NETLINK	270
#endif

int Netlink::Open(reply_fn_t&& default_msg_handler_fn, bool multicast) {
    std::unique_lock<std::mutex> _lock(_run_mutex);

    if (_start) {
        return 0;
    }

    if (!_quite) {
        Logger::Info("Opening audit NETLINK socket");
    }
    int fd = socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_AUDIT);
    if (fd < 0)  {
        auto saved_errno = errno;
        if (errno == EINVAL || errno == EPROTONOSUPPORT || errno == EAFNOSUPPORT) {
            Logger::Error("Could not open AUDIT NETLINK socket: No support in kernel");
        } else {
            Logger::Error("Error opening AUDIT NETLINK socket: %s", std::strerror(errno));
        }
        return -saved_errno;
    }

    sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = 0;
    if (multicast) {
        addr.nl_groups = 1; // AUDIT_NLGRP_READLOG
    } else {
        addr.nl_groups = 0;
    }

    if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        auto saved_errno = errno;
        Logger::Error("Failed to bind NETLINK socket: %s", std::strerror(errno));
        close(fd);
        return -saved_errno;
    }

    socklen_t addr_len = sizeof(addr);
    if (getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &addr_len) != 0) {
        auto saved_errno = errno;
        Logger::Error("Failed to get assigned NETLINK 'port': %s", std::strerror(errno));
        close(fd);
        return -saved_errno;
    }

    _pid = addr.nl_pid;

    int on = 1;
    if (setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &on, sizeof(on)) != 0) {
        Logger::Error("Cannot set NETLINK_NO_ENOBUFS option on audit NETLINK socket: %s", std::strerror(errno));
    }

    _fd = fd;
    _default_msg_handler_fn = std::move(default_msg_handler_fn);

    _lock.unlock();

    if (!_quite) {
        Logger::Info("Netlink: starting");
    }
    Start();

    return 0;
}

void Netlink::Close() {
    Stop();
}

int Netlink::Send(uint16_t type, const void* data, size_t len, reply_fn_t&& reply_fn) {
    std::unique_lock<std::mutex> _lock(_run_mutex);

    if (_stop) {
        return -ENOTCONN;
    }

    nlmsghdr *nl = reinterpret_cast<nlmsghdr*>(_data.data());
    nl->nlmsg_type = type;
    nl->nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK;

    // Make sure the seq is unique and not in use
    uint32_t seq = 0;
    do {
        seq = _sequence++;
        if (_sequence == 0) {
            _sequence = 1;
        }
    } while (_replies.count(seq) > 0 || _known_seq.count(seq) > 0);

    nl->nlmsg_seq = seq;
    nl->nlmsg_pid = _pid;

    if (data != nullptr && len > 0) {
        nl->nlmsg_len = static_cast<uint32_t>(NLMSG_SPACE(len));
        memcpy(NLMSG_DATA(nl), data, len);
    } else {
        nl->nlmsg_len = static_cast<uint32_t>(NLMSG_SPACE(0));
    }

    sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = 0;
    addr.nl_groups = 0;

    std::future<int> future;
    auto reply_rec = std::make_shared<ReplyRec>(std::move(reply_fn));
    future = reply_rec->_promise.get_future();
    _known_seq.emplace(nl->nlmsg_seq, reply_rec->_req_age);
    auto rep = _replies.emplace(nl->nlmsg_seq, reply_rec);

    _lock.unlock();

    int ret;
    do {
        ret = sendto(_fd, nl, nl->nlmsg_len, 0, (struct sockaddr *) &addr, sizeof(addr));
    } while (ret < 0 && errno == EINTR);
    _lock.lock();

    if (ret < 0) {
        auto saved_errno = errno;
        Logger::Warn("Netlink: sendto() failed: %s", std::strerror(errno));
        _replies.erase(nl->nlmsg_seq);
        _known_seq.erase(nl->nlmsg_seq);
        errno = saved_errno;
        return -saved_errno;
    }

    _lock.unlock();

    future.wait();
    auto retval = future.get();
    return retval;
}

int Netlink::AuditGet(audit_status& status) {
    ::memset(&status, 0, sizeof(status));
    bool received_response = false;
    auto ret = Send(AUDIT_GET, nullptr, 0, [&status,&received_response](uint16_t type, uint16_t flags, const void* data, size_t len) -> bool {
        if (type == AUDIT_GET) {
            std::memcpy(&status, data, std::min(len, sizeof(status)));
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

// Return 1 on success, 0 on timeout, -1 on failure, throw exception if fn threw an exception
int Netlink::AuditSet(audit_status& status) {
    return Send(AUDIT_SET, &status, sizeof(status), nullptr);
}

int Netlink::AuditGetPid(uint32_t& pid) {
    audit_status status;
    auto ret = AuditGet(status);
    if (ret == 0) {
        pid = status.pid;
    }
    return ret;
}

int Netlink::AuditSetPid(uint32_t pid) {
    audit_status status;
    ::memset(&status, 0, sizeof(status));
    status.mask = AUDIT_STATUS_PID;
    status.pid = pid;
    return AuditSet(status);
}

int Netlink::AuditGetEnabled(uint32_t& enabled) {
    audit_status status;
    auto ret = AuditGet(status);
    if (ret == 0) {
        enabled = status.enabled;
    }
    return ret;
}

int Netlink::AuditSetEnabled(uint32_t enabled) {
    audit_status status;
    ::memset(&status, 0, sizeof(status));
    status.mask = AUDIT_STATUS_ENABLED;
    status.enabled = enabled;
    return AuditSet(status);
}

int wait_readable(int fd, long timeout) {
    struct pollfd fds;
    fds.fd = fd;
    fds.events = POLLIN;
    fds.revents = 0;

    auto ret = poll(&fds, 1, static_cast<int>(timeout));
    if (ret < 0) {
        if (errno != EINTR) {
            return -1;
        } else {
            return 0;
        }
    } else if (ret == 0) {
        return 0;
    }

    if ((fds.revents & POLLIN) != 0) {
        return 1;
    } if ((fds.revents & (POLLHUP&POLLRDHUP)) != 0) {
        return 0;
    } else {
        return -1;
    }
}

void Netlink::flush_replies(bool is_exit) {
    std::lock_guard<std::mutex> _lock(_run_mutex);

    auto now = std::chrono::steady_clock::now();
    for (auto itr = _replies.begin(); itr != _replies.end();) {
        if (is_exit || itr->second->_req_age < now - std::chrono::milliseconds(1000)) {
            // Set promise value if it has not already been set
            if (!itr->second->_done) {
                auto age = std::chrono::duration_cast<std::chrono::milliseconds>(now - itr->second->_req_age).count();
                itr->second->_done = true;
                try {
                    if (is_exit) {
                        itr->second->_promise.set_value(-ECANCELED);
                    } else {
                        itr->second->_promise.set_value(-ETIMEDOUT);
                    }
                } catch (const std::exception &ex) {
                    Logger::Error("Unexpected exception while trying to set promise value for NETLINK reply: %s",
                                  ex.what());
                }
            }
            itr = _replies.erase(itr);
        } else {
            ++itr;
        }
    }

    // Hold onto _known_seq entries for 10 seconds.
    // This should avoid "Unexpected seq" log messages in the rare case where the req timed out before all reply messages could be received
    for (auto itr = _known_seq.begin(); itr != _known_seq.end();) {
        if (is_exit || itr->second < now - std::chrono::seconds(10)) {
            itr = _known_seq.erase(itr);
        } else {
            ++itr;
        }
    }
}

void Netlink::on_stopping() {
    std::unique_lock<std::mutex> _lock(_run_mutex);
    if (_fd > 0) {
        close(_fd);
    }
    _fd = -1;
}

void Netlink::on_stop() {
    flush_replies(true);
}

void Netlink::run() {
    std::unique_lock<std::mutex> _lock(_run_mutex);
    int fd = _fd;

    _lock.unlock();
    std::chrono::steady_clock::time_point last_flush = std::chrono::steady_clock::now();
    while(!IsStopping()) {
        while(!IsStopping()) {
            long timeout = -1;
            _lock.lock();
            if (!_replies.empty()) {
                timeout = 250;
            }
            _lock.unlock();
            auto ret = wait_readable(fd, timeout);
            if (ret < 0) {
                if (!IsStopping()) {
                    Logger::Error("Unexpected error while waiting for NETLINK socket to become readable: %s", std::strerror(errno));
                }
                return;
            } else if (ret == 0) {
                flush_replies(IsStopping());
                last_flush = std::chrono::steady_clock::now();
                if (IsStopping()) {
                    return;
                }
            } else {
                break;
            }
        }

        if (last_flush < std::chrono::steady_clock::now() - std::chrono::milliseconds(250)) {
            flush_replies(IsStopping());
            last_flush = std::chrono::steady_clock::now();
        }

        sockaddr_nl nladdr;
        socklen_t nladdrlen = sizeof(nladdr);
        int len;
        do {
            len = recvfrom(fd, _data.data(), _data.size(), 0, (struct sockaddr *) &nladdr, &nladdrlen);
        } while (len < 0 && errno == EINTR && !IsStopping());

        if (IsStopping()) {
            return;
        }

        if (len < 0) {
            Logger::Error("Error receiving packet from AUDIT NETLINK socket: (%d) %s", errno, std::strerror((errno)));
            return;
        }

        if (nladdrlen != sizeof(nladdr)) {
            Logger::Error("Error receiving packet from AUDIT NETLINK socket: Bad address size");
            return;
        }

        if (nladdr.nl_pid) {
            Logger::Error("Received AUDIT NETLINK packet from non-kernel source: pid == %d", nladdr.nl_pid);
            continue;
        }

        auto nl = reinterpret_cast<nlmsghdr*>(_data.data());

        if (!NLMSG_OK(nl, len)) {
            Logger::Error("Received invalid AUDIT NETLINK packet: Type %d, Flags %X, Seq %d", nl->nlmsg_type, nl->nlmsg_flags, nl->nlmsg_seq);
            continue;
        }

        size_t payload_len = len - static_cast<size_t>(reinterpret_cast<char*>(NLMSG_DATA(nl)) - reinterpret_cast<char*>(_data.data()));

        handle_msg(nl->nlmsg_type, nl->nlmsg_flags, nl->nlmsg_seq, NLMSG_DATA(nl), payload_len);
    }

    flush_replies(true);
}

void Netlink::handle_msg(uint16_t msg_type, uint16_t msg_flags, uint32_t msg_seq, const void* payload_data, size_t payload_len) {
    reply_fn_t* fn_ptr = nullptr;
    bool done = false;

    std::shared_ptr<ReplyRec> reply;

    if (msg_seq != 0) {
        // The seq is non-zero so this message should be a reply to a request
        // look for the reply_fn associates with this seq #
        std::lock_guard<std::mutex> _lock(_run_mutex);
        auto itr = _replies.find(msg_seq);
        if (itr != _replies.end()) {
            reply = itr->second;
            fn_ptr = &reply->_fn;
            done = reply->_done;
            reply->_req_age = std::chrono::steady_clock::now();
            _known_seq[msg_seq] = reply->_req_age;
        } else {
            // No ReplyRec found for the seq #
            done = true;
            // Only print a warning if the seq # is not known
            if (_known_seq.count(msg_seq) == 0) {
                Logger::Warn("Received unexpected NETLINK packet (Type: %d, Flags: 0x%X, Seq: %d, Size: %ld",
                             msg_type, msg_flags, msg_seq, payload_len);
            }
        }
    } else {
        if (_default_msg_handler_fn) {
            fn_ptr = &_default_msg_handler_fn;
        } else {
            done = true;
            Logger::Warn(
                    "Received NETLINK packet With Seq 0 and no default handler is defined (Type: %d, Flags: 0x%X, Size: %ld",
                    msg_type, msg_flags, payload_len);
        }
    }

    // If the request hasn't been marked done, has a valid reply_fn associated, and the message is not of type NLMSG_ERRROR or NLMSG_DONE
    // then call the reply_fn
    if (!done && fn_ptr != nullptr && *fn_ptr && msg_type != NLMSG_ERROR && msg_type != NLMSG_DONE) {
        try {
            if (!(*fn_ptr)(msg_type, msg_flags, payload_data, payload_len) && msg_seq > 0) {
                // The reply_fn returned false, so mark the request as complete.
                std::lock_guard<std::mutex> _lock(_run_mutex);
                if (reply) {
                    reply->_done = true;
                    reply->_promise.set_value(0);
                }
                return;
            }
        } catch (const std::exception &ex) {
            if (msg_seq > 0) {
                // The reply_fn threw an exception, try to propagate the exception through the request promise
                std::lock_guard<std::mutex> _lock(_run_mutex);
                if (reply) {
                    try {
                        reply->_promise.set_exception(std::current_exception());
                        reply->_done = true;
                    } catch (const std::exception &ex) {
                        Logger::Error(
                                "Unexpected exception while trying to set exception in NETLINK msg reply promise: %s",
                                ex.what());
                    }
                    _replies.erase(msg_seq);
                }
            }
            return;
        }
    }

    if (msg_seq != 0) {
        if (msg_type == NLMSG_ERROR) {
            auto err = reinterpret_cast<const nlmsgerr *>(payload_data);
            std::lock_guard<std::mutex> _lock(_run_mutex);
            // If the request failed, or the request succeeded but no response is expected then set the value to err->error
            // If !fn then no response is expected and the return value is err->error (typically == 0)
            if (err->error != 0 || fn_ptr == nullptr || !(*fn_ptr)) {
                if (reply) {
                    if (!reply->_done) {
                        reply->_done = true;
                        reply->_promise.set_value(err->error);
                    }
                    _replies.erase(msg_seq);
                }
                _known_seq.erase(msg_seq);
            }
        } else if ((msg_flags & NLM_F_MULTI) == 0 || msg_type == NLMSG_DONE) {
            std::lock_guard<std::mutex> _lock(_run_mutex);
            if (reply) {
                if (!reply->_done) {
                    reply->_promise.set_value(0);
                    reply->_done = true;
                }
                _replies.erase(msg_seq);
            }
            _known_seq.erase(msg_seq);
        }
    }
}

int NetlinkRetry(const std::function<int()>& fn) {
    std::function<bool(int)> p = [](int ret) { return ret == -ETIMEDOUT; };
    auto ret = Retry(5, std::chrono::milliseconds(1), true, fn, p);
    return ret.first;
}
