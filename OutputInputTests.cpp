/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/


#include "Output.h"

//#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE "OutputInputTests"

#include <boost/test/unit_test.hpp>

#include "TempDir.h"
#include "IEventWriter.h"
#include "OperationalStatus.h"
#include "Inputs.h"
#include "InputBuffer.h"
#include "Gate.h"
#include "Signals.h"
#include "StringUtils.h"
#include "UnixDomainWriter.h"

bool BuildEvent(std::shared_ptr<EventBuilder>& builder, uint64_t sec, uint32_t msec, uint64_t serial, int seq) {
    if (!builder->BeginEvent(sec, msec, serial, 1)) {
        return false;
    }
    if (!builder->BeginRecord(1, "TEST", "", 1)) {
        builder->CancelEvent();
        return false;
    }
    if (!builder->AddField("seq", std::to_string(seq), std::string_view(), field_type_t::UNCLASSIFIED)) {
        builder->CancelEvent();
        return false;
    }
    if(!builder->EndRecord()) {
        builder->CancelEvent();
        return false;
    }
    return builder->EndEvent() == 1;
}

int GetEventSeq(const Event& event) {
    auto rec = event.begin();
    auto f = rec.begin();
    std::string rec_seq(f.RawValuePtr(), f.RawValueSize());
    return stoi(rec_seq);
}

BOOST_AUTO_TEST_CASE( basic_test ) {
    TempDir dir("/tmp/OutputInputTests");

    std::string socket_path = "@input.socket@@@@";
    std::string status_socket_path = dir.Path() + "/status.socket";

    std::mutex log_mutex;
    std::vector<std::string> log_lines;
    Logger::SetLogFunction([&log_mutex,&log_lines](const char* ptr, size_t size){
        std::lock_guard<std::mutex> lock(log_mutex);
        log_lines.emplace_back(ptr, size);
    });

    Signals::Init();
    Signals::Start();

    auto queue = PriorityQueue::Open(dir.Path(), 8, 4*1024,8, 0, 100, 0);
    auto event_queue = std::make_shared<EventQueue>(queue);
    auto builder = std::make_shared<EventBuilder>(event_queue, DefaultPrioritizer::Create(0));

    auto output_config = std::make_unique<Config>(std::unordered_map<std::string, std::string>({
        {"output_format","raw"},
        {"output_socket", socket_path},
        {"enable_ack_mode", "true"},
        {"ack_queue_size", "10"},
        {"ack_timeout", "1000"}
    }));
    auto writer_factory = std::shared_ptr<IEventWriterFactory>(static_cast<IEventWriterFactory*>(new RawOnlyEventWriterFactory()));
    Output output("output", "", queue, writer_factory, nullptr);
    output.Load(output_config);

    auto operational_status = std::make_shared<OperationalStatus>("", nullptr);

    Inputs inputs(socket_path, operational_status);
    if (!inputs.Initialize()) {
        BOOST_FAIL("Failed to initialize inputs");
    }

    Gate start_gate;
    Gate done_gate;
    std::vector<std::string> _outputs;

    constexpr int num_events = 100;

    std::thread input_thread([&]() {
        Signals::InitThread();
        start_gate.Wait(Gate::OPEN, -1);
        int num_received = 0;
        while (num_received < num_events) {
            if (!inputs.HandleData([&num_received,&_outputs](void* ptr, size_t size) {
                _outputs.emplace_back(reinterpret_cast<char*>(ptr), size);
                num_received += 1;
            })) {
                break;
            };
        }
        done_gate.Open();
    });

    inputs.Start();
    output.Start();

    // Wait for output to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    for (int i = 0; i < num_events; i++) {
        if (!BuildEvent(builder, 1, 1, i, i)) {
            BOOST_FAIL("Failed to build event");
        }
    }

    // Wait long enough for the ack queue to fill completely, but mush less than the ack timeout
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    start_gate.Open();

    if (!done_gate.Wait(Gate::OPEN, 1000)) {
        BOOST_FAIL("Time out waiting for inputs");
    }

    output.Stop();
    inputs.Stop();
    queue->Close();
    input_thread.join();

    for (auto& msg : log_lines) {
        if (starts_with(msg, "Output(output): Timeout waiting for Acks")) {
            BOOST_FAIL("Found 'Timeout waiting for Acks' in log output");
        }
    }

    BOOST_REQUIRE_EQUAL(num_events, _outputs.size());

    for (int i = 0; i < num_events; i++) {
        Event event(_outputs[i].data(), _outputs[i].size());
        BOOST_REQUIRE_EQUAL(i, event.Serial());
    }
}

BOOST_AUTO_TEST_CASE( same_event_id_test ) {
    TempDir dir("/tmp/OutputInputTests");

    std::string socket_path = "@input.socket@@@@@@";
    std::string status_socket_path = dir.Path() + "/status.socket";

    std::mutex log_mutex;
    std::vector<std::string> log_lines;
    Logger::SetLogFunction([&log_mutex,&log_lines](const char* ptr, size_t size){
        std::lock_guard<std::mutex> lock(log_mutex);
        log_lines.emplace_back(ptr, size);
    });

    Signals::Init();
    Signals::Start();

    auto queue = PriorityQueue::Open(dir.Path(), 8, 4*1024,8, 0, 100, 0);
    auto event_queue = std::make_shared<EventQueue>(queue);
    auto builder = std::make_shared<EventBuilder>(event_queue, DefaultPrioritizer::Create(0));

    auto output_config = std::make_unique<Config>(std::unordered_map<std::string, std::string>({
        {"output_format","raw"},
        {"output_socket", socket_path},
        {"enable_ack_mode", "true"},
        {"ack_queue_size", "10"},
        {"ack_timeout", "1000"}
    }));
    auto writer_factory = std::shared_ptr<IEventWriterFactory>(static_cast<IEventWriterFactory*>(new RawOnlyEventWriterFactory()));
    Output output("output", "", queue, writer_factory, nullptr);
    output.Load(output_config);

    auto operational_status = std::make_shared<OperationalStatus>("", nullptr);

    Inputs inputs(socket_path, operational_status);
    if (!inputs.Initialize()) {
        BOOST_FAIL("Failed to initialize inputs");
    }

    Gate start_gate;
    Gate done_gate;
    std::vector<std::string> _outputs;

    constexpr int num_events = 100;

    std::thread input_thread([&]() {
        Signals::InitThread();
        start_gate.Wait(Gate::OPEN, -1);
        int num_received = 0;
        while (num_received < num_events) {
            if (!inputs.HandleData([&num_received,&_outputs](void* ptr, size_t size) {
                _outputs.emplace_back(reinterpret_cast<char*>(ptr), size);
                num_received += 1;
            })) {
                break;
            };
        }
        done_gate.Open();
    });

    inputs.Start();
    output.Start();

    // Wait for output to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    for (int i = 0; i < num_events; i++) {
        if (!BuildEvent(builder, 1, 1, 1, i)) {
            BOOST_FAIL("Failed to build event");
        }
    }

    // Wait long enough for the ack queue to fill completely, but mush less than the ack timeout
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    start_gate.Open();

    if (!done_gate.Wait(Gate::OPEN, 1000)) {
        BOOST_FAIL("Time out waiting for inputs");
    }

    output.Stop();
    inputs.Stop();
    queue->Close();
    input_thread.join();

    for (auto& msg : log_lines) {
        if (starts_with(msg, "Output(output): Timeout waiting for Acks")) {
            BOOST_FAIL("Found 'Timeout waiting for Acks' in log output");
        }
    }

    BOOST_REQUIRE_EQUAL(num_events, _outputs.size());

    for (int i = 0; i < num_events; i++) {
        Event event(_outputs[i].data(), _outputs[i].size());
        auto event_seq = GetEventSeq(event);
        BOOST_REQUIRE_EQUAL(i, event_seq);
    }
}

BOOST_AUTO_TEST_CASE( dropped_acks_test ) {
    TempDir dir("/tmp/OutputInputTests");

    std::string socket_path = "@input.socket@@@@@@";
    std::string status_socket_path = dir.Path() + "/status.socket";

    std::mutex log_mutex;
    std::vector<std::string> log_lines;
    Logger::SetLogFunction([&log_mutex,&log_lines](const char* ptr, size_t size){
        std::lock_guard<std::mutex> lock(log_mutex);
        log_lines.emplace_back(ptr, size);
    });

    Signals::Init();
    Signals::Start();

    auto queue = PriorityQueue::Open(dir.Path(), 8, 4*1024,8, 0, 100, 0);
    auto event_queue = std::make_shared<EventQueue>(queue);
    auto builder = std::make_shared<EventBuilder>(event_queue, DefaultPrioritizer::Create(0));

    auto output_config = std::make_unique<Config>(std::unordered_map<std::string, std::string>({
        {"output_format","raw"},
        {"output_socket", socket_path},
        {"enable_ack_mode", "true"},
        {"ack_timeout", "100"}
    }));
    auto writer_factory = std::shared_ptr<IEventWriterFactory>(static_cast<IEventWriterFactory*>(new RawOnlyEventWriterFactory()));
    Output output("output", "", queue, writer_factory, nullptr);
    output.Load(output_config);

    Gate done_gate;
    std::vector<std::string> _outputs;

    constexpr int num_events = 100;
    constexpr uint64_t end_serial = 0xDEADBEEFDEADBEEF;

    done_gate.Open();

    std::thread input_thread([&]() {
        Signals::InitThread();

        UnixDomainListener udl(socket_path);
        if (!udl.Open()) {
            return;
        }

        done_gate.Close();

        bool stop = false;
        bool drop = true;
        std::array<uint8_t, 1024> data;
        RawEventReader reader;

        while(!stop) {
            auto fd = udl.Accept();
            IOBase io(fd);

            while (!stop) {
                auto ret = reader.ReadEvent(data.data(), data.size(), &io, nullptr);
                if (ret <= 0) {
                    io.Close();
                    break;
                }
                Event event(data.data(), ret);
                Logger::Info("Input: Recevied %ld", event.Serial());
                if (event.Serial() == end_serial) {
                    Logger::Info("Input: Recevied End");
                    reader.WriteAck(event, &io);
                    stop = true;
                    break;
                }
                if (!drop) {
                    Logger::Info("Input: Sending Ack");
                    reader.WriteAck(event, &io);
                    _outputs.emplace_back(reinterpret_cast<char *>(data.data()), ret);
                }
                drop = !drop;
            }
        }
        done_gate.Open();
    });

    if (!done_gate.Wait(Gate::CLOSED, 10000)) {
        BOOST_FAIL("Time out waiting input thread to be ready");
    }

    output.Start();

    // Wait for output to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    for (int i = 0; i < num_events; i++) {
        if (!BuildEvent(builder, 1, 1, i, i)) {
            BOOST_FAIL("Failed to build event");
        }
    }
    for (int i = 0; i < 10; i++) {
        if (!BuildEvent(builder, 1, 1, end_serial, 0)) {
            BOOST_FAIL("Failed to build event");
        }
    }

    if (!done_gate.Wait(Gate::OPEN, 15000)) {
        BOOST_FAIL("Time out waiting for inputs");
    }

    output.Stop();
    queue->Close();
    input_thread.join();

    int timeout_count = 0;
    for (auto& msg : log_lines) {
        if (starts_with(msg, "Output(output): Timeout waiting for ack")) {
            timeout_count += 1;
        }
    }

    BOOST_REQUIRE_EQUAL(num_events, timeout_count);
    BOOST_REQUIRE_EQUAL(num_events, _outputs.size());

    for (int i = 0; i < num_events; i++) {
        Event event(_outputs[i].data(), _outputs[i].size());
        auto event_seq = GetEventSeq(event);
        BOOST_REQUIRE_EQUAL(i, event_seq);
    }
}

BOOST_AUTO_TEST_CASE( dropped_conn_test ) {
    TempDir dir("/tmp/OutputInputTests");

    std::string socket_path = dir.Path() + "/input.socket";
    std::string status_socket_path = dir.Path() + "/status.socket";

    std::mutex log_mutex;
    std::vector<std::string> log_lines;
    Logger::SetLogFunction([&log_mutex,&log_lines](const char* ptr, size_t size){
        std::lock_guard<std::mutex> lock(log_mutex);
        log_lines.emplace_back(ptr, size);
    });

    Signals::Init();
    Signals::Start();

    auto queue = PriorityQueue::Open(dir.Path(), 8, 4*1024,8, 0, 100, 0);
    auto event_queue = std::make_shared<EventQueue>(queue);
    auto builder = std::make_shared<EventBuilder>(event_queue, DefaultPrioritizer::Create(0));

    auto output_config = std::make_unique<Config>(std::unordered_map<std::string, std::string>({
        {"output_format","raw"},
        {"output_socket", socket_path},
        {"enable_ack_mode", "true"},
        {"ack_queue_size", "10"},
        {"ack_timeout", "1000"}
    }));
    auto writer_factory = std::shared_ptr<IEventWriterFactory>(static_cast<IEventWriterFactory*>(new RawOnlyEventWriterFactory()));
    Output output("output", "", queue, writer_factory, nullptr);
    output.Load(output_config);

    Gate done_gate;
    std::vector<std::string> _outputs;

    constexpr int num_events = 100;
    constexpr uint64_t end_serial = 0xDEADBEEFDEADBEEF;

    done_gate.Open();

    std::thread input_thread([&]() {
        Signals::InitThread();

        UnixDomainListener udl(socket_path);
        if (!udl.Open()) {
            return;
        }

        done_gate.Close();

        bool stop = false;
        bool drop = false;
        std::array<uint8_t, 1024> data;
        RawEventReader reader;

        while(!stop) {
            auto fd = udl.Accept();
            IOBase io(fd);

            Logger::Info("Input Connected");

            while (!stop) {
                auto ret = reader.ReadEvent(data.data(), data.size(), &io, nullptr);
                if (ret <= 0) {
                    io.Close();
                    break;
                }
                Event event(data.data(), ret);
                if (event.Serial() == end_serial) {
                    reader.WriteAck(event, &io);
                    io.Close();
                    stop = true;
                    break;
                }
                auto seq = GetEventSeq(event);
                if (!drop) {
                    Logger::Info("INGEST: %d", seq);
                    drop = !drop;
                    reader.WriteAck(event, &io);
                    _outputs.emplace_back(reinterpret_cast<char *>(data.data()), ret);
                } else {
                    Logger::Info("DROP: %d", seq);
                    drop = !drop;
                    io.Close();
                    break;
                }
            }
        }
        done_gate.Open();
    });

    if (!done_gate.Wait(Gate::CLOSED, 10000)) {
        BOOST_FAIL("Time out waiting input thread to be ready");
    }

    output.Start();

    // Wait for output to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    for (int i = 0; i < num_events; i++) {
        if (!BuildEvent(builder, 1, 1, i, i)) {
            BOOST_FAIL("Failed to build event");
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    for (int i = 0; i < 10; i++) {
        if (!BuildEvent(builder, 1, 1, end_serial, 0)) {
            BOOST_FAIL("Failed to build event");
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    if (!done_gate.Wait(Gate::OPEN, 100000)) {
        BOOST_FAIL("Time out waiting for inputs");
    }

    output.Stop();
    queue->Close();
    input_thread.join();

    for (auto& msg : log_lines) {
        if (starts_with(msg, "Output(output): Timeout waiting for Acks")) {
            BOOST_FAIL("Found 'Timeout waiting for Acks' in log output");
        }
    }

    BOOST_REQUIRE_EQUAL(num_events, _outputs.size());

    for (int i = 0; i < num_events; i++) {
        Event event(_outputs[i].data(), _outputs[i].size());
        auto event_seq = GetEventSeq(event);
        BOOST_REQUIRE_EQUAL(i, event_seq);
    }
}

BOOST_AUTO_TEST_CASE( oversized_event_test ) {
    TempDir dir("/tmp/OutputInputTests");

    std::string socket_path = dir.Path() + "/input.socket";
    std::string status_socket_path = dir.Path() + "/status.socket";

    std::mutex log_mutex;
    std::vector<std::string> log_lines;
    Logger::SetLogFunction([&log_mutex,&log_lines](const char* ptr, size_t size){
        std::lock_guard<std::mutex> lock(log_mutex);
        log_lines.emplace_back(ptr, size);
    });

    Signals::Init();
    Signals::Start();

    auto operational_status = std::make_shared<OperationalStatus>("", nullptr);

    Inputs inputs(socket_path, operational_status);
    if (!inputs.Initialize()) {
        BOOST_FAIL("Failed to initialize inputs");
    }

    Gate done_gate;
    std::vector<std::string> _outputs;

    std::thread input_thread([&]() {
        Signals::InitThread();
        while (!Signals::IsExit()) {
            if (!inputs.HandleData([&_outputs](void* ptr, size_t size) {
                _outputs.emplace_back(reinterpret_cast<char*>(ptr), size);
            })) {
                break;
            };
        }
        done_gate.Open();
    });

    inputs.Start();

    UnixDomainWriter udw(socket_path);

    if (!udw.Open()) {
        BOOST_FAIL("Failed to open inputs socket");
    }

    std::array<uint8_t, InputBuffer::MAX_DATA_SIZE+1> _data;
    _data.fill(0);
    uint32_t header;
    header = static_cast<uint32_t>(1) << 24;
    header |= static_cast<uint32_t>(InputBuffer::MAX_DATA_SIZE+1);
    reinterpret_cast<uint32_t*>(_data.data())[0] = header;

    if (dynamic_cast<IWriter*>(&udw)->WriteAll(_data.data(), _data.size()) != IO::OK) {
        BOOST_FAIL("Failed write data to input socket");
    }

    if (dynamic_cast<IWriter*>(&udw)->WriteAll(_data.data(), _data.size()) != IO::OK) {
        BOOST_FAIL("Failed write data to input socket");
    }

    if (dynamic_cast<IWriter*>(&udw)->WriteAll(_data.data(), _data.size()) != IO::OK) {
        BOOST_FAIL("Failed write data to input socket");
    }

    udw.Close();

    inputs.Stop();

    if (!done_gate.Wait(Gate::OPEN, 1000)) {
        BOOST_FAIL("Time out waiting for inputs thread to exit");
    }

    input_thread.join();

    int lcnt = 0;
    for (auto& msg : log_lines) {
        if (msg == "RawEventReader: Message size (262145) in header is too large (> 262144), reading and discarding message contents\n") {
            lcnt += 1;
        }
    }

    if (lcnt != 3) {
        BOOST_FAIL("Expected 3 'header it too large' messages");
    }
}
