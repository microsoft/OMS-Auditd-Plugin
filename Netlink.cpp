//
// Created by tad on 2/7/19.
//

#include "Netlink.h"
#include "Logger.h"

#include <sys/socket.h>
#include <linux/netlink.h>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>


bool Netlink::Open(reply_fn_t default_msg_handler_fn) {
    std::unique_lock<std::mutex> _lock(_run_mutex);

    if (_start) {
        return true;
    }

    Logger::Info("Opening audit NETLINK socket");
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_AUDIT);
    if (fd < 0)  {
        if (errno == EINVAL || errno == EPROTONOSUPPORT || errno == EAFNOSUPPORT) {
            Logger::Error("Could not open AUDIT NETLINK socket: No support in kernel");
        } else {
            Logger::Error("Error opening AUDIT NETLINK socket: %s", std::strerror(errno));
        }
        return false;
    }

    _fd = fd;
    _default_msg_handler_fn = default_msg_handler_fn;

    _lock.unlock();

    Logger::Info("Netlink: starting");
    Start();

    return true;
}

void Netlink::Close() {
    Stop();
}

int Netlink::Send(uint16_t type, uint16_t flags, void* data, size_t len, reply_fn_t reply_fn) {
    std::unique_lock<std::mutex> _lock(_run_mutex);

    if (_stop) {
        return CLOSED;
    }

    nlmsghdr *nl = reinterpret_cast<nlmsghdr*>(_data.data());
    nl->nlmsg_type = type;
    nl->nlmsg_flags = flags;
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
    if (flags & (NLM_F_REQUEST|NLM_F_ACK) != 0) {
        auto ret = _replies.emplace(nl->nlmsg_seq, ReplyRec(std::move(reply_fn), flags));
        future = ret.first->second._promise.get_future();
    }

    int ret;
    do {
        ret = sendto(_fd, nl, nl->nlmsg_len, 0, (struct sockaddr *) &addr, sizeof(addr));
    } while (ret < 0 && errno == EINTR);

    if (ret < 0) {
        Logger::Warn("Netlink: sendto() failed: %s", std::strerror(errno));
        if (flags & (NLM_F_REQUEST|NLM_F_ACK) != 0) {
            _replies.erase(nl->nlmsg_seq);
        }
        return FAILED;
    }

    if (flags & (NLM_F_REQUEST|NLM_F_ACK) == 0) {
        return SUCCESS;
    }

    _lock.unlock();
    future.wait();

    return future.get();
}

int Netlink::AuditGet(audit_status& status) {
    int err;
    auto ret = Send(AUDIT_GET, NLM_F_REQUEST|NLM_F_ACK, nullptr, 0, [&err, &status](uint16_t type, uint16_t flags, void* data, size_t len) -> bool {
        if (type == NLMSG_ERROR) {
            err = reinterpret_cast<nlmsgerr*>(data)->error;
            return err == 0;
        } else if (type == AUDIT_GET) {
            std::memcpy(&status, data, std::min(len, sizeof(status)));
            return false;
        }
    });
    if (err != 0) {
        return FAILED;
    }
    return ret;
}

// Return 1 on success, 0 on timeout, -1 on failure, throw exception if fn threw an exception
int Netlink::AuditSet(audit_status& status) {
    int err;
    auto ret = Send(AUDIT_SET, NLM_F_REQUEST|NLM_F_ACK, &status, sizeof(status), [&err](uint16_t type, uint16_t flags, void* data, size_t len) -> bool {
        if (type == NLMSG_ERROR) {
            err = reinterpret_cast<nlmsgerr*>(data)->error;
            return false;
        }
    });
    if (err != 0) {
        return FAILED;
    }
    return ret;
}

int Netlink::AuditGetPid(uint32_t& pid) {
    audit_status status;
    auto ret = AuditGet(status);
    if (ret == SUCCESS) {
        pid = status.pid;
    }
    return ret;
}

int Netlink::AuditSetPid(uint32_t pid) {
    audit_status status;
    status.mask = AUDIT_STATUS_PID;
    status.pid = pid;
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

    for (auto itr = _replies.begin(); itr != _replies.end();) {
        if (is_exit || itr->second._req_time < std::chrono::steady_clock::now() - std::chrono::milliseconds(200)) {
            if (!itr->second._done) {
                try {
                    if (is_exit) {
                        itr->second._promise.set_value(CLOSED);
                    } else {
                        itr->second._promise.set_value(TIMEOUT);
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
                timeout = 200;
            }
            _lock.unlock();
            auto ret = wait_readable(fd, timeout);
            if (ret < 0) {
                if (!IsStopping()) {
                    Logger::Error("Unexpected error while waiting for NETLINK socket to become readable: %s", std::strerror(errno));
                }
                return;
            } else if (ret == 0) {
                flush_replies(false);
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
            Logger::Error("Error receiving packet from AUDIT NETLINK socket: %s", std::strerror((errno)));
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


        nlmsghdr *nl = reinterpret_cast<nlmsghdr*>(_data.data());

        if (!NLMSG_OK(nl, len)) {
            Logger::Error("Received invalid AUDIT NETLINK packet: Type %d, Flags %X, Seq %d", nl->nlmsg_type, nl->nlmsg_flags, nl->nlmsg_seq);
            continue;
        }

        size_t payload_len = len - static_cast<size_t>(reinterpret_cast<char*>(NLMSG_DATA(nl)) - reinterpret_cast<char*>(_data.data()));

        //Logger::Debug("Recieved NETLINK packet [%d, %d, %d] %d bytes", nl->nlmsg_type, nl->nlmsg_flags, nl->nlmsg_seq, payload_len);

        reply_fn_t fn = _default_msg_handler_fn;
        uint16_t flags = 0;
        bool done = false;

        if (nl->nlmsg_seq != 0) {
            _lock.lock();
            auto itr = _replies.find(nl->nlmsg_seq);
            if (itr != _replies.end()) {
                fn = itr->second._fn;
                flags = itr->second._flags;
                done = itr->second._done;
            } else {
                done = true;
                Logger::Info("Received unexpected NETLINK packet (Type: %d, Flags: %X, Seq: %d, Size: %d", nl->nlmsg_type, nl->nlmsg_flags, nl->nlmsg_seq, nl->nlmsg_len);
            }
            _lock.unlock();
        } else {
            if (_default_msg_handler_fn) {
                fn = _default_msg_handler_fn;
            } else {
                done = true;
                Logger::Info("Received NETLINK packet With Seq 0 and no default handler is defined (Type: %d, Flags: %X, Size: %d", nl->nlmsg_type, nl->nlmsg_flags, nl->nlmsg_len);
            }
        }

        if (!done) {
            try {
                if (!fn(nl->nlmsg_type, nl->nlmsg_flags, NLMSG_DATA(nl), payload_len)) {
                    _lock.lock();
                    auto itr = _replies.find(nl->nlmsg_seq);
                    if (itr != _replies.end()) {
                        itr->second._promise.set_value(SUCCESS);
                        itr->second._done = true;
                    }
                    _lock.unlock();
                    continue;
                }
            } catch (const std::exception &ex) {
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
                continue;
            }
        }

        if (nl->nlmsg_seq != 0) {
            if (nl->nlmsg_type == NLMSG_ERROR) {
                nlmsgerr *err = reinterpret_cast<nlmsgerr *>(NLMSG_DATA(nl));
                if (err->error != 0) {
                    if (nl->nlmsg_seq != 0) {
                        _lock.lock();
                        auto itr = _replies.find(nl->nlmsg_seq);
                        if (itr != _replies.end() && !itr->second._done) {
                            itr->second._promise.set_value(FAILED);
                            itr->second._done = true;
                        }
                        _replies.erase(itr);
                        _lock.unlock();
                    }
                }
            } else if (nl->nlmsg_type != NLMSG_ERROR || (flags & NLM_F_ACK) == 0) {
                if ((flags & NLM_F_MULTI) == 0 || nl->nlmsg_type == NLMSG_DONE) {
                    if (nl->nlmsg_seq != 0) {
                        _lock.lock();
                        auto itr = _replies.find(nl->nlmsg_seq);
                        if (itr != _replies.end() && !itr->second._done) {
                            itr->second._promise.set_value(SUCCESS);
                            itr->second._done = true;
                        }
                        _replies.erase(itr);
                        _lock.unlock();
                    }
                }
            }
        }
    }

    flush_replies(true);
}
