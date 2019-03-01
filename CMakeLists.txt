####
# microsoft-oms-auditd-plugin
#
# Copyright (c) Microsoft Corporation
#
# All rights reserved. 
#
# MIT License
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
####

cmake_minimum_required(VERSION 2.6)
project(auoms)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -ggdb")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -ggdb")

include_directories(BEFORE ${CMAKE_BINARY_DIR}/../ext_include)

add_executable(auomscollect
        auomscollect.cpp
        IO.cpp
        Event.cpp
        OMSEventWriterConfig.cpp
        OMSEventWriter.cpp
        JSONEventWriter.cpp
        MsgPackEventWriter.cpp
        TextEventWriter.cpp
        Signals.cpp
        Queue.cpp
        UnixDomainWriter.cpp
        Logger.cpp
        Config.cpp
        UserDB.cpp
        RunBase.cpp
        Output.cpp
        StringUtils.cpp
        RawEventRecord.cpp
        RawEventAccumulator.cpp
        LookupTables.cpp
        StdinReader.cpp
        Netlink.cpp
        FileWatcher.cpp
        Gate.h
        Defer.h
)

# See https://gcc.gnu.org/onlinedocs/libstdc++/manual/license.html
# and https://www.gnu.org/licenses/gcc-exception-3.1-faq.en.html
# for why it is safe to use -static-libgcc -static-libstdc++
set_target_properties(auomscollect PROPERTIES LINK_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro -Wl,-z,now -static-libgcc -static-libstdc++ -Wl,--no-as-needed -lrt -Wl,--as-needed")

target_link_libraries(auomscollect
        dl
        pthread
        rt
)

install(TARGETS
        auomscollect
        RUNTIME DESTINATION ${CMAKE_BINARY_DIR}/release/bin
)

add_executable(auomsforward
        auomsforward.cpp
        IO.cpp
        Event.cpp
        OMSEventWriterConfig.cpp
        OMSEventWriter.cpp
        JSONEventWriter.cpp
        MsgPackEventWriter.cpp
        TextEventWriter.cpp
        RawEventProcessor.cpp
        Signals.cpp
        Queue.cpp
        UnixDomainWriter.cpp
        Logger.cpp
        Config.cpp
        UserDB.cpp
        RunBase.cpp
        InputBuffer.h
        Inputs.cpp
        Input.cpp
        Outputs.cpp
        Output.cpp
        ProcessInfo.cpp
        ProcFilter.cpp
        StringUtils.cpp
        LookupTables.cpp
        Interpret.cpp
        CollectionMonitor.cpp
        Netlink.cpp
)

# See https://gcc.gnu.org/onlinedocs/libstdc++/manual/license.html
# and https://www.gnu.org/licenses/gcc-exception-3.1-faq.en.html
# for why it is safe to use -static-libgcc -static-libstdc++
#set_target_properties(auoms PROPERTIES LINK_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro -Wl,-z,now -Wl,--wrap=memcpy -static-libgcc -static-libstdc++ -Wl,--no-as-needed -lrt -Wl,--as-needed")
set_target_properties(auomsforward PROPERTIES LINK_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro -Wl,-z,now -static-libgcc -static-libstdc++ -Wl,--no-as-needed -lrt -Wl,--as-needed")

target_link_libraries(auomsforward
        dl
        pthread
        rt
)

install(TARGETS
        auomsforward
        RUNTIME DESTINATION ${CMAKE_BINARY_DIR}/release/bin
)

add_executable(test_netlink
        test_netlink.cpp
        Netlink.cpp
        RunBase.cpp
        Signals.cpp
        Logger.cpp
)

# See https://gcc.gnu.org/onlinedocs/libstdc++/manual/license.html
# and https://www.gnu.org/licenses/gcc-exception-3.1-faq.en.html
# for why it is safe to use -static-libgcc -static-libstdc++
#set_target_properties(auoms PROPERTIES LINK_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro -Wl,-z,now -Wl,--wrap=memcpy -static-libgcc -static-libstdc++ -Wl,--no-as-needed -lrt -Wl,--as-needed")
set_target_properties(test_netlink PROPERTIES LINK_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro -Wl,-z,now -static-libgcc -static-libstdc++ -Wl,--no-as-needed -lrt -Wl,--as-needed")

target_link_libraries(test_netlink
        pthread
        rt
)

install(TARGETS
        test_netlink
        RUNTIME DESTINATION ${CMAKE_BINARY_DIR}/release/bin
)

add_executable(testreceiver
        Event.cpp
        Logger.cpp
        testreceiver.cpp
)

set_target_properties(testreceiver PROPERTIES LINK_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro -Wl,-z,now -static-libgcc -static-libstdc++ -Wl,--no-as-needed -lrt -Wl,--as-needed")

install(TARGETS
        testreceiver
        RUNTIME DESTINATION ${CMAKE_BINARY_DIR}/release/bin
)

add_executable(fakeaudispd
        fakeaudispd.cpp
)

set_target_properties(fakeaudispd PROPERTIES LINK_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro -Wl,-z,now -static-libgcc -static-libstdc++ -Wl,--no-as-needed -lrt -Wl,--as-needed")

install(TARGETS
        fakeaudispd
        RUNTIME DESTINATION ${CMAKE_BINARY_DIR}/release/bin
)

add_executable(file2sock
        file2sock.cpp
        UnixDomainWriter.cpp
        IO.cpp
        Logger.cpp
        Event.cpp
)

set_target_properties(file2sock PROPERTIES LINK_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro -Wl,-z,now -static-libgcc -static-libstdc++ -Wl,--no-as-needed -lrt -Wl,--as-needed")

install(TARGETS
        file2sock
        RUNTIME DESTINATION ${CMAKE_BINARY_DIR}/release/bin
)

#Setup CMake to run tests
enable_testing()

#Prep ourselves for compiling boost
find_package(Boost 1.48 COMPONENTS unit_test_framework REQUIRED)
include_directories (${Boost_INCLUDE_DIRS})

add_executable(ConfigTests
        TempFile.cpp
        Config.cpp
        ConfigTests.cpp
)

target_link_libraries(ConfigTests ${Boost_LIBRARIES})

add_test(Config ${CMAKE_BINARY_DIR}/ConfigTests --log_sink=ConfigTests.log --report_sink=ConfigTests.report)

add_executable(EventTests
        TempFile.cpp
        Logger.cpp
        Queue.cpp
        Event.cpp
        EventTests.cpp
)

target_link_libraries(EventTests ${Boost_LIBRARIES})

add_test(Event ${CMAKE_BINARY_DIR}/EventTests --log_sink=EventTests.log --report_sink=EventTests.report)

add_executable(QueueTests
        TempFile.cpp
        Logger.cpp
        Queue.cpp
        QueueTests.cpp
)

target_link_libraries(QueueTests ${Boost_LIBRARIES})

add_test(Queue ${CMAKE_BINARY_DIR}/QueueTests --log_sink=QueueTests.log --report_sink=QueueTests.report)

add_executable(UserDBTests
        TempDir.cpp
        Logger.cpp
        UserDB.cpp
        UserDBTests.cpp
)

target_link_libraries(UserDBTests ${Boost_LIBRARIES} pthread)

add_test(UserDB ${CMAKE_BINARY_DIR}/UserDBTests --log_sink=UserDBTests.log --report_sink=UserDBTests.report)

add_executable(StringTests
        StringUtils.cpp
        StringTests.cpp
)

target_link_libraries(StringTests ${Boost_LIBRARIES})

add_test(String ${CMAKE_BINARY_DIR}/StringTests --log_sink=StringTests.log --report_sink=StringTests.report)

add_executable(EventProcessorTests
        EventProcessorTests.cpp
        Event.cpp
        TextEventWriter.cpp
        AuditEventProcessor.cpp
        Signals.cpp
        Logger.cpp
        Config.cpp
        UserDB.cpp
        RunBase.cpp
        ProcessInfo.cpp
        ProcFilter.cpp
        StringUtils.cpp
        TempDir.cpp
        TestEventData.cpp
)

target_link_libraries(EventProcessorTests ${Boost_LIBRARIES}
        audit
        auparse
        dl
        pthread
        rt
)

add_test(EventProcessor ${CMAKE_BINARY_DIR}/EventProcessorTests --log_sink=EventProcessorTests.log --report_sink=EventProcessorTests.report)


add_executable(OMSEventWriterTests
        OMSEventWriterTests.cpp
        OMSEventWriter.cpp
        OMSEventWriterConfig.cpp
        Event.cpp
        TextEventWriter.cpp
        Logger.cpp
        Config.cpp
        StringUtils.cpp
        TestEventData.cpp
)

target_link_libraries(OMSEventWriterTests ${Boost_LIBRARIES})

add_test(OMSEventWriter ${CMAKE_BINARY_DIR}/OMSEventWriterTests --log_sink=OMSEventWriterTests.log --report_sink=OMSEventWriterTests.report)

add_executable(autest
        autest.cpp
        RawEventRecord.cpp
)
