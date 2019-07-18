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


int Netlink::Open(reply_fn_t default_msg_handler_fn) {
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

    _fd = fd;
    _default_msg_handler_fn = default_msg_handler_fn;

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

int Netlink::Send(uint16_t type, const void* data, size_t len, reply_fn_t reply_fn) {
    std::unique_lock<std::mutex> _lock(_run_mutex);

    if (_stop) {
        return -ENOTCONN;
    }

    nlmsghdr *nl = reinterpret_cast<nlmsghdr*>(_data.data());
    nl->nlmsg_type = type;
    nl->nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK;
    nl->nlmsg_seq = _sequence++;
    if (_sequence == 0) {
        _sequence = 1;
    }

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
    auto rep = _replies.emplace(nl->nlmsg_seq, ReplyRec(std::move(reply_fn)));
    future = rep.first->second._promise.get_future();
    _known_seq.emplace(nl->nlmsg_seq, rep.first->second._req_time);

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

    return future.get();
}

int Netlink::AuditGet(audit_status& status) {
    ::memset(&status, 0, sizeof(status));
    bool received_response = false;
    auto ret = Send(AUDIT_GET, nullptr, 0, [&status,&received_response](uint16_t type, uint16_t flags, const void* data, size_t len) -> bool {
        if (type == AUDIT_GET) {
            std::memcpy(&status, data, std::min(len, sizeof(status)));
            received_response = true;
            return false;
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
        if (is_exit || itr->second._req_time < now - std::chrono::milliseconds(200)) {
            // Set promise value if it has not already been set
            if (!itr->second._done) {
                itr->second._done = true;
                try {
                    if (is_exit) {
                        itr->second._promise.set_value(-ECANCELED);
                    } else {
                        itr->second._promise.set_value(-ETIMEDOUT);
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

    // Hold onto _known_seq entries for a whole second.
    // This should avoid "Unexpected seq" log messages in the rare case where the req timed out before all reply messages could be received
    for (auto itr = _known_seq.begin(); itr != _known_seq.end();) {
        if (is_exit || itr->second < now - std::chrono::seconds(1)) {
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
                if (IsStopping()) {
                    return;
                }
            } else {
                break;
            }
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

        reply_fn_t fn = _default_msg_handler_fn;
        bool done = false;

        if (nl->nlmsg_seq != 0) {
            _lock.lock();
            auto itr = _replies.find(nl->nlmsg_seq);
            if (itr != _replies.end()) {
                fn = itr->second._fn;
                done = itr->second._done;
            } else {
                done = true;
                if (_known_seq.count(nl->nlmsg_seq) == 0) {
                    Logger::Warn("Received unexpected NETLINK packet (Type: %d, Flags: %X, Seq: %d, Size: %d",
                                 nl->nlmsg_type, nl->nlmsg_flags, nl->nlmsg_seq, nl->nlmsg_len);
                }
            }
            _lock.unlock();
        } else {
            if (_default_msg_handler_fn) {
                fn = _default_msg_handler_fn;
            } else {
                done = true;
                Logger::Warn(
                        "Received NETLINK packet With Seq 0 and no default handler is defined (Type: %d, Flags: %X, Size: %d",
                        nl->nlmsg_type, nl->nlmsg_flags, nl->nlmsg_len);
            }
        }

        if (!done && fn && nl->nlmsg_type != NLMSG_ERROR && nl->nlmsg_type != NLMSG_DONE) {
            try {
                if (!fn(nl->nlmsg_type, nl->nlmsg_flags, NLMSG_DATA(nl), payload_len) && nl->nlmsg_seq > 0) {
                    _lock.lock();
                    auto itr = _replies.find(nl->nlmsg_seq);
                    if (itr != _replies.end()) {
                        itr->second._done = true;
                        itr->second._promise.set_value(0);
                    }
                    _lock.unlock();
                    continue;
                }
            } catch (const std::exception &ex) {
                if (nl->nlmsg_seq > 0) {
                    _lock.lock();
                    auto itr = _replies.find(nl->nlmsg_seq);
                    if (itr != _replies.end()) {
                        try {
                            itr->second._promise.set_exception(std::current_exception());
                            itr->second._done = true;
                        } catch (const std::exception &ex) {
                            Logger::Error(
                                    "Unexpected exception while trying to set exception in NETLINK msg reply promise: %s",
                                    ex.what());
                        }
                        _replies.erase(itr);
                    }
                    _lock.unlock();
                }
                continue;
            }
        }

        if (nl->nlmsg_seq != 0) {
            if (nl->nlmsg_type == NLMSG_ERROR) {
                auto err = reinterpret_cast<nlmsgerr *>(NLMSG_DATA(nl));
                _lock.lock();
                // If the request failed, or the request succedded but no response is expected then set the value to err->error
                // If !fn then no response is expected and the return value is err->error (typically == 0)
                if (err->error != 0 || !fn) {
                    auto itr = _replies.find(nl->nlmsg_seq);
                    if (itr != _replies.end()) {
                        if (!itr->second._done) {
                            itr->second._done = true;
                            itr->second._promise.set_value(err->error);
                        }
                        _replies.erase(itr);
                    }
                }
                _known_seq.erase(nl->nlmsg_seq);
                _lock.unlock();
            } else if ((nl->nlmsg_flags & NLM_F_MULTI) == 0 || nl->nlmsg_type == NLMSG_DONE) {
                _lock.lock();
                auto itr = _replies.find(nl->nlmsg_seq);
                if (itr != _replies.end()) {
                    if (!itr->second._done) {
                        itr->second._promise.set_value(0);
                        itr->second._done = true;
                    }
                    _replies.erase(itr);
                }
                _known_seq.erase(nl->nlmsg_seq);
                _lock.unlock();
            }
        }
    }

    flush_replies(true);
}

int NetlinkRetry(std::function<int()> fn) {
    std::function<bool(int)> p = [](int ret) { return ret == -ETIMEDOUT; };
    auto ret = Retry(5, std::chrono::milliseconds(1), true, fn, p);
    return ret.first;
}
