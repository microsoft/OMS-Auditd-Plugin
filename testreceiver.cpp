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
#include <thread>
#include <mutex>
#include <string>

#include <rapidjson/document.h>
#include "rapidjson/filereadstream.h"
#include "rapidjson/error/en.h"
#include "rapidjson/filewritestream.h"
#include "rapidjson/writer.h"

extern "C" {
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <fcntl.h>
}

void usage()
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  testreceiver -s <sock path> -p <protocol> [-a] [-e] [-o <file>]\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "    -s <sock path> - The path to the socket file.\n");
    fprintf(stderr, "    -p <protocol>  - The expected protocol ('oms', 'raw', 'pass'). The 'pass' mode is straight pass through.\n");
    fprintf(stderr, "    -a             - Enable ack mode. Only valid with 'raw' mode.\n");
    fprintf(stderr, "    -o <file>      - Path to output file (default stdout)\n");
    fprintf(stderr, "    -e             - Exit after first disconnect.\n");
    fprintf(stderr, "    -r             - Write raw events in raw form to output.\n");
    exit(1);
}

bool get_event_id_from_json(const rapidjson::Document& doc, EventId& event_id) {
    if (!doc.IsArray()) {
        fprintf(stderr, "JSON isn't an array");
        return false;
    }

    if (doc.Size() < 2) {
        fprintf(stderr, "JSON array too small");
        return false;
    }

    const rapidjson::Value& event = doc[1];
    if (!event.IsObject()) {
        fprintf(stderr, "array[1] is not an object");
        return false;
    }

    if (!event.HasMember("Timestamp")) {
        fprintf(stderr, "Event 'Timestamp' field is missing");
        return false;
    }

    if (!event.HasMember("SerialNumber")) {
        fprintf(stderr, "Event 'SerialNumber' field is missing");
        return false;
    }

    std::string ts_str = event["Timestamp"].GetString();
    std::string ser_str = event["Timestamp"].GetString();

    auto idx = ts_str.find_first_of('.');
    if (idx == std::string::npos) {
        fprintf(stderr, "Invalid Timestamp value");
        return false;
    }

    std::string sec_str = ts_str.substr(0, idx);
    std::string msec_str = ts_str.substr(idx+1);

    event_id = EventId(stoull(sec_str, nullptr, 10),
                       static_cast<uint32_t>(stoul(msec_str, nullptr, 10)),
                       stoull(ser_str, nullptr, 10));
    return true;
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
        fprintf(stderr, "Ack write failed");
        return false;
    }
    return true;
}

void handle_oms_connection(int fd, int out_fd, bool ack) {
    FILE* fp = fdopen(fd, "r");
    auto out = fdopen(out_fd, "w");
    std::array<char, 4096> in_buffer;
    std::array<char, 4096> out_buffer;
    rapidjson::FileReadStream frs(fp, in_buffer.data(), in_buffer.size());


    for(;;) {
        rapidjson::Document d;
        d.ParseStream<rapidjson::kParseStopWhenDoneFlag, rapidjson::Document::EncodingType, rapidjson::FileReadStream>(frs);
        if (d.HasParseError()) {
            fclose(out);
            throw std::runtime_error(rapidjson::GetParseError_En(d.GetParseError()));
        }
        EventId event_id;
        if (!get_event_id_from_json(d, event_id)) {
            fclose(out);
            return;
        }
        fprintf(out, "\n======================================================================\n");
        fprintf(out, "%lld.%ld:%lld\n",
                static_cast<unsigned long long>(event_id.Seconds()),
                static_cast<unsigned long>(event_id.Milliseconds()),
                static_cast<unsigned long long>(event_id.Serial()));

        rapidjson::FileWriteStream fws(out, out_buffer.data(), out_buffer.size());
        rapidjson::Writer<rapidjson::FileWriteStream> w(fws);
        d.Accept(w);

        if (ack) {
            if (!write_text_ack(fp, event_id)) {
                fclose(out);
            }
        }
    }
}

void handle_raw_connection(int fd, int out_fd, bool ack, bool raw_out) {
    std::array<uint8_t, 1024*256> data;
    auto out = fdopen(out_fd, "w");
    if (out == nullptr) {
        fprintf(stderr, "fdopen failed\n");
        return;
    }

    for (;;) {
        auto nread = 0;
        auto nleft = 4;
        while (nleft > 0) {
            auto nr = read(fd, data.data() + nread, nleft);
            if (nr <= 0) {
                if (nr < 0) {
                    fclose(out);
                    throw std::system_error(errno, std::system_category(), "Read frame size");
                } else {
                    fprintf(stderr, "EOF in input\n");
                    fclose(out);
                    return;
                }
            }
            nleft -= nr;
            nread += nr;
        }
        auto size = *reinterpret_cast<uint32_t *>(data.data());
        if (size <= 4 || size > 1024 * 256) {
            fclose(out);
            throw std::runtime_error("Invalid frame size");
        }
        nread = 4;
        nleft = size - 4;
        while (nleft > 0) {
            auto nr = read(fd, data.data() + nread, nleft);
            if (nr <= 0) {
                if (nr < 0) {
                    fclose(out);
                    throw std::system_error(errno, std::system_category(), "Read frame");
                } else {
                    fclose(out);
                    throw std::runtime_error("Read frame failed: EOF");
                }
            }
            nleft -= nr;
            nread += nr;
        }

        Event event(data.data(), size);
        if (raw_out) {
            if (out_fd != 1) {
                fprintf(stderr, "%lld.%ld:%lld\n",
                        static_cast<unsigned long long>(event.Seconds()),
                        static_cast<unsigned long>(event.Milliseconds()),
                        static_cast<unsigned long long>(event.Serial()));
            }
            write(out_fd, data.data(), size);
        } else {
            fprintf(out, "\n======================================================================\n");
            fprintf(out, "%lld.%ld:%lld\n",
                    static_cast<unsigned long long>(event.Seconds()),
                    static_cast<unsigned long>(event.Milliseconds()),
                    static_cast<unsigned long long>(event.Serial()));

            for (auto rec : event) {
                fprintf(out, "    %d: %s\n", rec.RecordType(), rec.RecordTypeNamePtr());
                for (auto f : rec) {
                    if (f.InterpValueSize() > 0) {
                        fprintf(out, "\t%s\n\t    RAW: %s\n\t    INTERP: %s\n", f.FieldNamePtr(), f.RawValuePtr(),
                                f.InterpValuePtr());
                    } else {
                        fprintf(out, "\t%s\n\t    RAW: %s\n", f.FieldNamePtr(), f.RawValuePtr());
                    }
                }
            }
        }

        if (ack) {
            std::array<uint8_t, 8+8+4> ack_data;
            *reinterpret_cast<uint64_t*>(ack_data.data()) = event.Seconds();
            *reinterpret_cast<uint32_t*>(ack_data.data()+8) = event.Milliseconds();
            *reinterpret_cast<uint64_t*>(ack_data.data()+12) = event.Serial();
            auto nw = write(fd, ack_data.data(), ack_data.size());
            if (nw != ack_data.size()) {
                fclose(out);
                throw std::runtime_error("Failed to write ack");
            }
        }
    }

}

void handle_pass_connection(int fd, int out_fd) {
    char data;

    for(;;) {
        int nr = read(fd, &data, 1);
        if (nr == 0) {
            fprintf(stderr, "EOF in input\n");
            close(out_fd);
            return;
        }
        else if (nr != 1) {
            throw std::runtime_error("Read failed");
        }

        write(out_fd, &data, 1);
    }
}

int main(int argc, char**argv) {
    std::string output_file = "-";
    std::string sock_path;
    std::string protocol;
    bool ack_mode = false;
    bool exit_mode = false;
    bool raw_out = false;

    int opt;
    while ((opt = getopt(argc, argv, "aeo:p:rs:")) != -1) {
        switch (opt) {
            case 'a':
                ack_mode = true;
                break;
            case 'e':
                exit_mode = true;
                break;
            case 'o':
                output_file = optarg;
                break;
            case 'p':
                protocol = optarg;
                break;
            case 'r':
                raw_out = true;
                break;
            case 's':
                sock_path = optarg;
                break;
            default:
                usage();
        }
    }

    if (protocol != "oms" && protocol != "raw" && protocol != "pass") {
        fprintf(stderr, "Invalid protocol\n");
        usage();
    }

    if (protocol == "pass" && ack_mode) {
        fprintf(stderr, "Ack mode not allowed when protocol is 'pass'\n");
        usage();
    }

    if (protocol == "pass" && raw_out) {
        fprintf(stderr, "Raw output not allowed when protocol is 'pass'\n");
        usage();
    }

    if (sock_path.empty()) {
        fprintf(stderr, "Missing sock path\n");
        usage();
    }

    try {
        int out_fd = -1;
        if (output_file == "-") {
            out_fd = 1;
        } else {
            out_fd = open(output_file.c_str(), O_WRONLY|O_CREAT|O_TRUNC, 0644);
            if (out_fd < 0) {
                throw std::system_error(errno, std::system_category(), "open("+output_file+")");
            }
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

        do {
            fprintf(stderr, "Waiting for connection\n");
            socklen_t x = 0;
            int fd = accept(lfd, NULL, &x);
            if (-1 == fd) {
                throw std::system_error(errno, std::system_category(), "accept()");
            }

            fprintf(stderr, "Connected\n");

            if (protocol == "oms") {
                handle_oms_connection(fd, out_fd, ack_mode);
            } else if (protocol == "raw") {
                handle_raw_connection(fd, out_fd, ack_mode, raw_out);
            } else if (protocol == "pass") {
                handle_pass_connection(fd, out_fd);
            } else {
                throw std::runtime_error("Unexpected protocol value: " + protocol);
            }
        } while (!exit_mode);
    } catch (std::exception& ex) {
        fprintf(stderr, "%s\n", ex.what());
        exit(1);
    }
    exit(0);
}