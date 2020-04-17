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

cmake_minimum_required(VERSION 2.8.12)
project(auoms)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -ggdb")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} -ggdb")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -ggdb")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} -ggdb")

if(DEFINED DO_STATIC_LINK)
    # See https://gcc.gnu.org/onlinedocs/libstdc++/manual/license.html
    # and https://www.gnu.org/licenses/gcc-exception-3.1-faq.en.html
    # for why it is safe to use -static-libgcc -static-libstdc++
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro -Wl,-z,now -static-libgcc -static-libstdc++ -Wl,--no-as-needed -lrt -Wl,--as-needed")
endif()

include_directories(BEFORE ${CMAKE_BINARY_DIR}/../ext_include)

if (NOT DEFINED ENV_CONFIG_PATH)
    set(ENV_CONFIG_PATH ${CMAKE_SOURCE_DIR}/build/env_config.h)
endif()

add_custom_command(
        OUTPUT ${CMAKE_SOURCE_DIR}/auoms_version.h
        COMMAND bash -c \"grep AUOMS_BUILDVERSION auoms.version | head -n 4 | cut -d'=' -f2 | tr '\\n' '.' | sed 's/^\\\([0-9][0-9]*\\.[0-9][0-9]*\\.[0-9][0-9]*\\.[0-9][0-9]*\\\)\\.*/\#define AUOMS_VERSION \\"\\1\\"/' > auoms_version.h\"
        MAIN_DEPENDENCY auoms.version
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_custom_command(
        OUTPUT ${CMAKE_SOURCE_DIR}/env_config.h
        COMMAND ln -f -s ${ENV_CONFIG_PATH} ${CMAKE_SOURCE_DIR}/env_config.h
        MAIN_DEPENDENCY ${ENV_CONFIG_PATH}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_executable(auomscollect
        env_config.h
        auomscollect.cpp
        IO.cpp
        Event.cpp
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
        StdinReader.cpp
        Netlink.cpp
        FileWatcher.cpp
        Gate.h
        Defer.h
        TranslateRecordType.cpp
        FileUtils.cpp
        Retry.h
        Metrics.cpp
        ProcMetrics.cpp
        Cache.h
)

# See https://gcc.gnu.org/onlinedocs/libstdc++/manual/license.html
# and https://www.gnu.org/licenses/gcc-exception-3.1-faq.en.html
# for why it is safe to use -static-libgcc -static-libstdc++
#set_target_properties(auomscollect PROPERTIES LINK_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro -Wl,-z,now -static-libgcc -static-libstdc++ -Wl,--no-as-needed -lrt -Wl,--as-needed")

target_link_libraries(auomscollect
        dl
        pthread
        rt
)

if(CMAKE_BUILD_TYPE MATCHES RelWithDebInfo)
    ADD_CUSTOM_COMMAND(TARGET auomscollect POST_BUILD
            COMMAND ${CMAKE_OBJCOPY} --only-keep-debug $<TARGET_FILE:auomscollect> ${CMAKE_BINARY_DIR}/auomscollect.debug
            COMMAND ${CMAKE_STRIP} -g $<TARGET_FILE:auomscollect>
            COMMAND ${CMAKE_OBJCOPY} --add-gnu-debuglink=auomscollect.debug $<TARGET_FILE:auomscollect>
    )
    install(FILES ${CMAKE_BINARY_DIR}/auomscollect.debug DESTINATION ${CMAKE_BINARY_DIR}/release/bin)
endif(CMAKE_BUILD_TYPE MATCHES RelWithDebInfo)

install(TARGETS
        auomscollect
        RUNTIME DESTINATION ${CMAKE_BINARY_DIR}/release/bin
)


add_executable(auoms
        env_config.h
        auoms.cpp
        auoms_version.h
        IO.cpp
        Event.cpp
        TextEventWriterConfig.cpp
        OMSEventWriter.cpp
        JSONEventWriter.cpp
        MsgPackEventWriter.cpp
        SyslogEventWriter.cpp
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
        ProcessTree.cpp
        FiltersEngine.cpp
        EventFilter.cpp
        StringUtils.cpp
        Interpret.cpp
        CollectionMonitor.cpp
        Netlink.cpp
        NetlinkAudit.cpp
        TranslateArch.cpp
        TranslateSyscall.cpp
        TranslateRecordType.cpp
        TranslateFieldType.cpp
        TranslateField.cpp
        TranslateErrno.cpp
        AuditRules.cpp
        AuditRulesMonitor.cpp
        KernelInfo.cpp
        Version.cpp
        UnixDomainListener.cpp
        OperationalStatus.cpp
        FileUtils.cpp
        ExecUtil.cpp
        StringTable.h
        ExecveConverter.cpp
        Metrics.cpp
        SyscallMetrics.cpp
        ProcMetrics.cpp
        SystemMetrics.cpp
)

# See https://gcc.gnu.org/onlinedocs/libstdc++/manual/license.html
# and https://www.gnu.org/licenses/gcc-exception-3.1-faq.en.html
# for why it is safe to use -static-libgcc -static-libstdc++
#set_target_properties(auoms PROPERTIES LINK_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro -Wl,-z,now -Wl,--wrap=memcpy -static-libgcc -static-libstdc++ -Wl,--no-as-needed -lrt -Wl,--as-needed")
#set_target_properties(auoms PROPERTIES LINK_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro -Wl,-z,now -static-libgcc -static-libstdc++ -Wl,--no-as-needed -lrt -Wl,--as-needed")

target_link_libraries(auoms
        dl
        pthread
        rt
)

if(CMAKE_BUILD_TYPE MATCHES RelWithDebInfo)
    ADD_CUSTOM_COMMAND(TARGET auoms POST_BUILD
            COMMAND ${CMAKE_OBJCOPY} --only-keep-debug $<TARGET_FILE:auoms> ${CMAKE_BINARY_DIR}/auoms.debug
            COMMAND ${CMAKE_STRIP} -g $<TARGET_FILE:auoms>
            COMMAND ${CMAKE_OBJCOPY} --add-gnu-debuglink=auoms.debug $<TARGET_FILE:auoms>
    )
    install(FILES ${CMAKE_BINARY_DIR}/auoms.debug DESTINATION ${CMAKE_BINARY_DIR}/release/bin)
endif(CMAKE_BUILD_TYPE MATCHES RelWithDebInfo)

install(TARGETS
        auoms
        RUNTIME DESTINATION ${CMAKE_BINARY_DIR}/release/bin
)

add_executable(auomsctl
        env_config.h
        auomsctl.cpp
        auoms_version.h
        Netlink.cpp
        NetlinkAudit.cpp
        RunBase.cpp
        Signals.cpp
        Logger.cpp
        TranslateArch.cpp
        TranslateSyscall.cpp
        TranslateRecordType.cpp
        TranslateFieldType.cpp
        TranslateField.cpp
        TranslateErrno.cpp
        AuditRules.cpp
        StringUtils.cpp
        KernelInfo.cpp
        Version.cpp
        IO.cpp
        UnixDomainWriter.cpp
        ExecUtil.cpp
        FileUtils.cpp
        UnixDomainListener.cpp
        Event.cpp
        UserDB.cpp
)

# See https://gcc.gnu.org/onlinedocs/libstdc++/manual/license.html
# and https://www.gnu.org/licenses/gcc-exception-3.1-faq.en.html
# for why it is safe to use -static-libgcc -static-libstdc++
#set_target_properties(auoms PROPERTIES LINK_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro -Wl,-z,now -Wl,--wrap=memcpy -static-libgcc -static-libstdc++ -Wl,--no-as-needed -lrt -Wl,--as-needed")
#set_target_properties(auomsctl PROPERTIES LINK_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro -Wl,-z,now -static-libgcc -static-libstdc++ -Wl,--no-as-needed -lrt -Wl,--as-needed")

target_link_libraries(auomsctl
        pthread
        rt
)

if(CMAKE_BUILD_TYPE MATCHES RelWithDebInfo)
    ADD_CUSTOM_COMMAND(TARGET auomsctl POST_BUILD
            COMMAND ${CMAKE_OBJCOPY} --only-keep-debug $<TARGET_FILE:auomsctl> ${CMAKE_BINARY_DIR}/auomsctl.debug
            COMMAND ${CMAKE_STRIP} -g $<TARGET_FILE:auomsctl>
            COMMAND ${CMAKE_OBJCOPY} --add-gnu-debuglink=auomsctl.debug $<TARGET_FILE:auomsctl>
    )
    install(FILES ${CMAKE_BINARY_DIR}/auomsctl.debug DESTINATION ${CMAKE_BINARY_DIR}/release/bin)
endif(CMAKE_BUILD_TYPE MATCHES RelWithDebInfo)

install(TARGETS
        auomsctl
        RUNTIME DESTINATION ${CMAKE_BINARY_DIR}/release/bin
)

add_executable(testreceiver
        testreceiver.cpp
        Event.cpp
        Logger.cpp
        UnixDomainListener.cpp
)

#set_target_properties(testreceiver PROPERTIES LINK_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro -Wl,-z,now -static-libgcc -static-libstdc++ -Wl,--no-as-needed -lrt -Wl,--as-needed")

install(TARGETS
        testreceiver
        RUNTIME DESTINATION ${CMAKE_BINARY_DIR}/release/bin
)

add_executable(fakeaudispd
        fakeaudispd.cpp
)

#set_target_properties(fakeaudispd PROPERTIES LINK_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro -Wl,-z,now -static-libgcc -static-libstdc++ -Wl,--no-as-needed -lrt -Wl,--as-needed")

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

#set_target_properties(file2sock PROPERTIES LINK_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro -Wl,-z,now -static-libgcc -static-libstdc++ -Wl,--no-as-needed -lrt -Wl,--as-needed")

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
        Signals.cpp
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
        auoms_version.h
        EventProcessorTests.cpp
        Event.cpp
        TextEventWriter.cpp
        RawEventProcessor.cpp
        RawEventAccumulator.cpp
        RawEventRecord.cpp
        Signals.cpp
        Logger.cpp
        Config.cpp
        UserDB.cpp
        RunBase.cpp
        ProcessInfo.cpp
        ProcFilter.cpp
        ProcessTree.cpp
        FiltersEngine.cpp
        StringUtils.cpp
        TempDir.cpp
        TestEventData.cpp
        TranslateRecordType.cpp
        TranslateSyscall.cpp
        TranslateFieldType.cpp
        TranslateField.cpp
        TranslateArch.cpp
        Interpret.cpp
        ExecveConverter.cpp
        Metrics.cpp
        Cache.h
)

target_link_libraries(EventProcessorTests ${Boost_LIBRARIES}
        audit
        auparse
        dl
        pthread
        rt
)

add_test(EventProcessor ${CMAKE_BINARY_DIR}/EventProcessorTests --log_sink=EventProcessorTests.log --report_sink=EventProcessorTests.report)

add_executable(ExecveConverterTests
        ExecveConverterTests.cpp
        ExecveConverter.cpp
        Event.cpp
        RawEventAccumulator.cpp
        RawEventRecord.cpp
        Logger.cpp
        StringUtils.cpp
        TranslateRecordType.cpp
        RunBase.cpp
        Metrics.cpp
)

target_link_libraries(ExecveConverterTests ${Boost_LIBRARIES}
        audit
        auparse
        dl
        pthread
        rt
)

add_test(ExecveConverter ${CMAKE_BINARY_DIR}/ExecveConverterTests --log_sink=ExecveConverterTests.log --report_sink=ExecveConverterTests.report)

add_executable(OMSEventWriterTests
        OMSEventWriterTests.cpp
        OMSEventWriter.cpp
        TextEventWriterConfig.cpp
        Event.cpp
        TextEventWriter.cpp
        Logger.cpp
        Config.cpp
        StringUtils.cpp
        TestEventData.cpp
        ProcFilter.cpp
        Signals.cpp
        UserDB.cpp
        RunBase.cpp
        ExecveConverter.cpp
)

target_link_libraries(OMSEventWriterTests ${Boost_LIBRARIES}
        pthread
)

add_test(OMSEventWriter ${CMAKE_BINARY_DIR}/OMSEventWriterTests --log_sink=OMSEventWriterTests.log --report_sink=OMSEventWriterTests.report)
