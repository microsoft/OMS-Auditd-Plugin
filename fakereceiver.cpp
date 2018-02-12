/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "Event.h"
#include "EventId.h"

#include <cstdio>
#include <iostream>
#include <thread>
#include <mutex>
#include <string>

#include <rapidjson/document.h>
#include "rapidjson/filereadstream.h"
#include "rapidjson/error/en.h"

extern "C" {
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netinet/in.h>
}

void usage()
{
    std::cerr << "Usage:\n"
            "fakereceiver -s <sock path> -p <protocol> [-a]\n"
            "\n"
            "-s <sock path> - The path to the socket file.\n"
            "-p <protocol>  - The expected protocol.\n"
            "-a             - Enable ack mode.\n"
            ;
    exit(1);
}

void get_event_id_from_json(const rapidjson::Document& doc, EventId& event_id) {
    if (!doc.IsArray()) {
        throw std::runtime_error("JSON isn't an array");
    }

    if (doc.Size() < 2) {
        throw std::runtime_error("JSON array too small");
    }

    const rapidjson::Value& event = doc[1];
    if (!event.IsObject()) {
        throw std::runtime_error("array[1] is not an object");
    }

    if (!event.HasMember("Timestamp")) {
        throw std::runtime_error("Event 'Timestamp' field is missing");
    }

    if (!event.HasMember("SerialNumber")) {
        throw std::runtime_error("Event 'SerialNumber' field is missing");
    }

    std::string ts_str = event["Timestamp"].GetString();
    std::string ser_str = event["Timestamp"].GetString();

    auto idx = ts_str.find_first_of('.');
    if (idx == std::string::npos) {
        throw std::runtime_error("Invalid Timestamp value");
    }

    std::string sec_str = ts_str.substr(0, idx);
    std::string msec_str = ts_str.substr(idx+1);

    event_id = EventId(stoull(sec_str, nullptr, 10),
                       static_cast<uint32_t>(stoul(msec_str, nullptr, 10)),
                       stoull(ser_str, nullptr, 10));
}

bool write_text_ack(FILE* fp, const EventId& event_id) {
    std::array<char, ((8+8+4)*2)+4> data;
    snprintf(data.data(), data.size(),
             "%016llX:%08lX:%016llX\n",
             static_cast<unsigned long long>(event_id.Seconds()),
             static_cast<unsigned long>(event_id.Milliseconds()),
             static_cast<unsigned long long>(event_id.Serial()));

    auto ret = fwrite(data.data(), data.size()-1, 1, fp);
    if (ret != data.size()-1) {
        throw std::runtime_error("Ack write failed");
    }
}

void handle_oms_connection(int fd, bool ack) {
    FILE* fp = fdopen(fd, "r");
    std::array<char, 4096> buffer;
    rapidjson::FileReadStream frs(fp, buffer.data(), buffer.size());

    for(;;) {
        rapidjson::Document d;
        d.ParseStream<rapidjson::kParseStopWhenDoneFlag, rapidjson::Document::EncodingType, rapidjson::FileReadStream>(frs);
        if (d.HasParseError()) {
            throw std::runtime_error(rapidjson::GetParseError_En(d.GetParseError()));
        }
        EventId event_id;
        get_event_id_from_json(d, event_id);
        printf("%lld.%ld:%lld\n",
                static_cast<unsigned long long>(event_id.Seconds()),
                static_cast<unsigned long>(event_id.Milliseconds()),
                static_cast<unsigned long long>(event_id.Serial()));

        if (ack) {
            write_text_ack(fp, event_id);
        }
    }
}

void handle_raw_connection(int fd, bool ack) {
    std::array<uint8_t, 1024*256> data;

    for (;;) {
        auto nread = 0;
        auto nleft = 4;
        while (nleft > 0) {
            auto nr = read(fd, data.data() + nread, nleft);
            if (nr <= 0) {
                if (nr < 0) {
                    throw std::system_error(errno, std::system_category(), "Read frame size");
                } else {
                    throw std::runtime_error("Read frame size failed: EOF");
                }
            }
            nleft -= nr;
            nread += nr;
        }
        auto size = *reinterpret_cast<uint32_t *>(data.data());
        if (size <= 4 || size > 1024 * 256) {
            throw std::runtime_error("Invalid frame size");
        }
        nread = 4;
        nleft = size - 4;
        while (nleft > 0) {
            auto nr = read(fd, data.data() + nread, nleft);
            if (nr <= 0) {
                if (nr < 0) {
                    throw std::system_error(errno, std::system_category(), "Read frame");
                } else {
                    throw std::runtime_error("Read frame failed: EOF");
                }
            }
            nleft -= nr;
            nread += nr;
        }

        Event event(data.data(), size);
        printf("%lld.%ld:%lld\n",
               static_cast<unsigned long long>(event.Seconds()),
               static_cast<unsigned long>(event.Milliseconds()),
               static_cast<unsigned long long>(event.Serial()));

        if (ack) {
            std::array<uint8_t, 8+8+4> ack_data;
            *reinterpret_cast<uint64_t*>(ack_data.data()) = event.Seconds();
            *reinterpret_cast<uint32_t*>(ack_data.data()+8) = event.Milliseconds();
            *reinterpret_cast<uint64_t*>(ack_data.data()+12) = event.Serial();
            auto nw = write(fd, ack_data.data(), ack_data.size());
            if (nw != ack_data.size()) {
                throw std::runtime_error("Failed to write ack");
            }
        }
    }

}

int main(int argc, char**argv) {
    std::string sock_path;
    std::string protocol;
    bool ack_mode = false;

    int opt;
    while ((opt = getopt(argc, argv, "ap:s:")) != -1) {
        switch (opt) {
            case 'a':
                ack_mode = true;
                break;
            case 'p':
                protocol = optarg;
                break;
            case 's':
                sock_path = optarg;
                break;
            default:
                usage();
        }
    }

    if (protocol != "oms" && protocol != "raw") {
        throw std::runtime_error("Invalid protocol");
    }

    if (sock_path.empty()) {
        throw std::runtime_error("Missing sock path");
    }

    int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (-1 == lfd)
    {
        throw std::system_error(errno, std::system_category(), "socket(AF_UNIX, SOCK_STREAM)");
    }

    unlink(sock_path.c_str());

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    sock_path.copy(addr.sun_path, sizeof(addr.sun_path));
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)))
    {
        close(lfd);
        throw std::system_error(errno, std::system_category(), std::string("bind(AF_UNIX, ") + sock_path + ")");
    }

    chmod(sock_path.c_str(), 0666);

    if (listen(lfd, 1) != 0) {
        throw std::system_error(errno, std::system_category(), "listen()");
    }

    for (;;) {
        std::cerr << "Waiting for connection" << std::endl;
        socklen_t x = 0;
        int fd = accept(lfd, NULL, &x);
        if (-1 == fd) {
            throw std::system_error(errno, std::system_category(), "accept()");
        }

        std::cerr << "Connected" << std::endl;

        if (protocol == "oms") {
            handle_oms_connection(fd, ack_mode);
        } else if (protocol == "raw") {
            handle_raw_connection(fd, ack_mode);
        } else {
            throw std::runtime_error("Unexpected protocol value: " + protocol);
        }
    }
}