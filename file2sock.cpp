/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <iostream>
#include <thread>
#include <mutex>
#include <string>
#include <cstring>

#include "UnixDomainWriter.h"
#include "RawEventReader.h"
#include "RawEventWriter.h"
#include "Logger.h"

extern "C" {
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
}

void usage()
{
    std::cerr <<
              "Usage:\n"
              "file2sock -s <socket path> -i <input file> [-t <input type>]\n"
              "\n"
              "-i <input file>   - The path to the input data file or '-' for stdin.\n"
              "-s <socket path>  - The path to the input socket.\n"
              "-t <input type>   - The input format 'raw', 'raw_ack', or 'text' (default 'text')\n"
            ;
    exit(1);
}

int main(int argc, char**argv) {
    std::string data_file;
    std::string data_file_type = "text";
    std::string socket_path;

    int opt;
    while ((opt = getopt(argc, argv, "i:s:t:")) != -1) {
        switch (opt) {
            case 'i':
                data_file = optarg;
                break;
            case 's':
                socket_path = optarg;
                break;
            case 't':
                data_file_type = optarg;
                break;
            default:
                usage();
        }
    }

    if (data_file.empty() || socket_path.empty()) {
        usage();
    }

    int fd = -1;
    if (data_file == "-") {
        fd = 1;
    } else {
        fd = open(data_file.c_str(), O_RDONLY);
        if (fd < 0) {
            Logger::Error("open(%s) failed: %s", data_file.c_str(), std::strerror(errno));
            exit(1);
        }
    }

    IOBase input(fd);

    UnixDomainWriter output(socket_path);
    Logger::Info("Connecting to '%s'", socket_path.c_str());
    if (!output.Open()) {
        Logger::Warn("Failed to connect to '%s': %s", socket_path.c_str(), std::strerror(errno));
        exit(1);
    }

    if (data_file_type == "text") {
        char data[1024];
        for (;;) {
            auto ret = input.Read(data, sizeof(data), nullptr);
            if (ret < 0) {
                input.Close();
                output.Close();
                Logger::Error("Read failed");
                exit(1);
            } else if (ret == 0) {
                input.Close();
                output.Close();
                exit(0);
            }
            ret = output.IWriter::WriteAll(data, ret);
            if (ret != IO::OK) {
                input.Close();
                output.Close();
                if (ret == IO::CLOSED) {
                    Logger::Error("output closed");
                } else {
                    Logger::Error("Write failed");
                }
                exit(1);
            }
        }
    } else if (data_file_type == "raw" || data_file_type == "raw_ack") {
        RawEventReader reader;
        RawEventWriter writer;
        for(;;) {
            char data[10*1024];
            auto ret = reader.ReadEvent(data, sizeof(data), &input, nullptr);
            if (ret < 0) {
                input.Close();
                output.Close();
                Logger::Error("Read failed");
                exit(1);
            } else if (ret == 0) {
                input.Close();
                output.Close();
                exit(0);
            }
            Event event(data, ret);
            ret = writer.WriteEvent(event, &output);
            if (ret < 0) {
                input.Close();
                output.Close();
                if (ret == IO::CLOSED) {
                    Logger::Error("output closed");
                } else {
                    Logger::Error("Write failed");
                }
                exit(1);
            } else if (ret == 0) {
                input.Close();
                output.Close();
                exit(0);
            }
            if (data_file_type == "raw_ack") {
                EventId event_id;
                ret = writer.ReadAck(event_id, &output);
                if (ret < 0) {
                    input.Close();
                    output.Close();
                    Logger::Error("Read ack failed");
                    exit(1);
                } else if (ret == 0) {
                    input.Close();
                    output.Close();
                    Logger::Error("output closed");
                    exit(0);
                }
            }
        }
    }
}
