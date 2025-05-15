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
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} -ggdb -Wl,-z,relro -Wl,-z,now -fstack-protector-strong -D_FORTIFY_SOURCE=2")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -ggdb")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} -ggdb -Wl,-z,relro -Wl,-z,now -fstack-protector-strong -D_FORTIFY_SOURCE=2")

if(DO_STATIC_LINK)
    # See https://gcc.gnu.org/onlinedocs/libstdc++/manual/license.html
    # and https://www.gnu.org/licenses/gcc-exception-3.1-faq.en.html
    # for why it is safe to use -static-libgcc -static-libstdc++
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro -Wl,-z,now -static-libgcc -static-libstdc++ -Wl,--no-as-needed -lrt -Wl,--as-needed")
    set(RE2_LIBS libre2.a)
else()
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}")
    set(RE2_LIBS re2)
endif()

if (DEPS_INCLUDE)
    include_directories(BEFORE ${DEPS_INCLUDE})
endif()

if (DEPS_LIB)
    link_directories(BEFORE ${DEPS_LIB})
endif()

if (NOT ENV_CONFIG_PATH)
    set(ENV_CONFIG_PATH ${CMAKE_SOURCE_DIR}/build/env_config.h)
endif()

if (NO_EXTRA_INTERP_PROTO)
    add_compile_definitions(NO_INTERP_EXTRA_PROTO)
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
        auoms_version.h
        auomscollect.cpp
        IO.cpp
        Event.cpp
        EventPrioritizer.cpp
        Signals.cpp
        SPSCDataQueue.cpp
        PriorityQueue.cpp
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
        TranslateArch.cpp
        TranslateRecordType.cpp
        TranslateSyscall.cpp
        FileUtils.cpp
        Retry.h
        Metrics.cpp
        ProcMetrics.cpp
        Cache.h
        LockFile.cpp
        CGroups.cpp
        CPULimits.cpp
        SchedPriority.cpp
        EventMatcher.cpp
        EventAggregator.cpp
)

target_compile_options(auomscollect PRIVATE "-Werror")

target_link_libraries(auomscollect
        ${RE2_LIBS}
        dl
        pthread
        rt
)

if(CMAKE_BUILD_TYPE MATCHES RelWithDebInfo)
    ADD_CUSTOM_COMMAND(TARGET auomscollect POST_BUILD
            COMMAND ${CMAKE_OBJCOPY} --only-keep-debug $<TARGET_FILE:auomscollect> ${CMAKE_BINARY_DIR}/auomscollect.dbg
            COMMAND ${CMAKE_STRIP} -g $<TARGET_FILE:auomscollect>
            COMMAND ${CMAKE_OBJCOPY} --add-gnu-debuglink=auomscollect.dbg $<TARGET_FILE:auomscollect>
    )
    install(FILES ${CMAKE_BINARY_DIR}/auomscollect.dbg DESTINATION ${CMAKE_BINARY_DIR}/release/bin)
endif(CMAKE_BUILD_TYPE MATCHES RelWithDebInfo)

install(TARGETS
        auomscollect
        RUNTIME DESTINATION ${CMAKE_BINARY_DIR}/release/bin
)


add_executable(auoms
        env_config.h
        auoms.cpp
        auoms_version.h
        AuomsConfig.cpp
        IO.cpp
        Event.cpp
        EventPrioritizer.cpp
        EventWriterConfig.cpp
        AbstractEventWriter.cpp
        OMSEventWriter.cpp
        FluentEventWriter.cpp
        SyslogEventWriter.cpp
        RawEventProcessor.cpp
        Signals.cpp
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
        Netlink.cpp
        NetlinkAudit.cpp
        CollectionMonitorBuilder.cpp
        AuditdCollectionMonitor.cpp
        NetlinkCollectionMonitor.cpp
        TranslateArch.cpp
        TranslateSyscall.cpp
        TranslateRecordType.cpp
        TranslateFieldType.cpp
        TranslateField.cpp
        TranslateErrno.cpp
        AuditRules.cpp
        AuditRulesMonitor.cpp
        AuditStatus.cpp AuditStatus.h
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
        PriorityQueue.cpp PriorityQueue.h
        LockFile.cpp
        CGroups.cpp
        CPULimits.cpp
        CmdlineRedactor.cpp
        EventMatcher.cpp
        EventAggregator.cpp
)

target_compile_options(auoms PRIVATE "-Werror")

target_link_libraries(auoms
        ${RE2_LIBS}
        dl
        pthread
        rt
)

if(CMAKE_BUILD_TYPE MATCHES RelWithDebInfo)
    ADD_CUSTOM_COMMAND(TARGET auoms POST_BUILD
            COMMAND ${CMAKE_OBJCOPY} --only-keep-debug $<TARGET_FILE:auoms> ${CMAKE_BINARY_DIR}/auoms.dbg
            COMMAND ${CMAKE_STRIP} -g $<TARGET_FILE:auoms>
            COMMAND ${CMAKE_OBJCOPY} --add-gnu-debuglink=auoms.dbg $<TARGET_FILE:auoms>
    )
    install(FILES ${CMAKE_BINARY_DIR}/auoms.dbg DESTINATION ${CMAKE_BINARY_DIR}/release/bin)
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
        AuditStatus.cpp AuditStatus.h
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
        KernelInfo.cpp
        Config.cpp
        CmdlineRedactor.cpp
)

target_compile_options(auomsctl PRIVATE "-Werror")

target_link_libraries(auomsctl
        ${RE2_LIBS}
        pthread
        rt
)

if(CMAKE_BUILD_TYPE MATCHES RelWithDebInfo)
    ADD_CUSTOM_COMMAND(TARGET auomsctl POST_BUILD
            COMMAND ${CMAKE_OBJCOPY} --only-keep-debug $<TARGET_FILE:auomsctl> ${CMAKE_BINARY_DIR}/auomsctl.dbg
            COMMAND ${CMAKE_STRIP} -g $<TARGET_FILE:auomsctl>
            COMMAND ${CMAKE_OBJCOPY} --add-gnu-debuglink=auomsctl.dbg $<TARGET_FILE:auomsctl>
    )
    install(FILES ${CMAKE_BINARY_DIR}/auomsctl.dbg DESTINATION ${CMAKE_BINARY_DIR}/release/bin)
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

install(TARGETS
        testreceiver
        RUNTIME DESTINATION ${CMAKE_BINARY_DIR}/release/bin
)

add_executable(fakeaudispd
        fakeaudispd.cpp
)

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

install(TARGETS
        file2sock
        RUNTIME DESTINATION ${CMAKE_BINARY_DIR}/release/bin
)

#Setup CMake to run tests
enable_testing()

if(DO_STATIC_LINK)
  set(Boost_USE_STATIC_LIBS ON)
endif()
find_package(Boost 1.48 COMPONENTS unit_test_framework REQUIRED)
include_directories (${Boost_INCLUDE_DIRS})

add_executable(ConfigTests
        TempFile.cpp
        Config.cpp
        ConfigTests.cpp
)

if(NOT DO_STATIC_LINK)
  target_compile_definitions(ConfigTests PUBLIC BOOST_TEST_DYN_LINK=1)
endif()

target_link_libraries(ConfigTests ${Boost_LIBRARIES})

add_test(Config ${CMAKE_BINARY_DIR}/ConfigTests --log_sink=ConfigTests.log --report_sink=ConfigTests.report)

add_executable(EventTests
        TempDir.cpp
        Logger.cpp
        PriorityQueue.cpp
        FileUtils.cpp
        Event.cpp
        EventTests.cpp
)

if(NOT DO_STATIC_LINK)
  target_compile_definitions(EventTests PUBLIC BOOST_TEST_DYN_LINK=1)
endif()

target_link_libraries(EventTests ${Boost_LIBRARIES}
        pthread
)

add_test(Event ${CMAKE_BINARY_DIR}/EventTests --log_sink=EventTests.log --report_sink=EventTests.report)

add_executable(QueueTests
        TempFile.cpp
        Logger.cpp
        Queue.cpp
        QueueTests.cpp
)

if(NOT DO_STATIC_LINK)
  target_compile_definitions(QueueTests PUBLIC BOOST_TEST_DYN_LINK=1)
endif()

target_link_libraries(QueueTests ${Boost_LIBRARIES})

add_test(Queue ${CMAKE_BINARY_DIR}/QueueTests --log_sink=QueueTests.log --report_sink=QueueTests.report)

add_executable(PriorityQueueTests
        TempDir.cpp
        Logger.cpp
        FileUtils.cpp
        PriorityQueue.cpp
        PriorityQueueTests.cpp
)

if(NOT DO_STATIC_LINK)
  target_compile_definitions(PriorityQueueTests PUBLIC BOOST_TEST_DYN_LINK=1)
endif()

target_link_libraries(PriorityQueueTests ${Boost_LIBRARIES} pthread)

add_test(PriorityQueue ${CMAKE_BINARY_DIR}/PriorityQueueTests --log_sink=PriorityQueueTests.log --report_sink=PriorityQueueTests.report)

add_executable(SPSCDataQueueTests
        Logger.cpp
        SPSCDataQueue.cpp
        SPSCDataQueueTests.cpp
)

if(NOT DO_STATIC_LINK)
  target_compile_definitions(SPSCDataQueueTests PUBLIC BOOST_TEST_DYN_LINK=1)
endif()

target_link_libraries(SPSCDataQueueTests ${Boost_LIBRARIES} pthread)

add_test(SPSCDataQueueTests ${CMAKE_BINARY_DIR}/SPSCDataQueueTests --log_sink=SPSCDataQueueTests.log --report_sink=SPSCDataQueueTests.report)

add_executable(UserDBTests
        TempDir.cpp
        Logger.cpp
        Signals.cpp
        UserDB.cpp
        UserDBTests.cpp
)

if(NOT DO_STATIC_LINK)
  target_compile_definitions(UserDBTests PUBLIC BOOST_TEST_DYN_LINK=1)
endif()

target_link_libraries(UserDBTests ${Boost_LIBRARIES} pthread)

add_test(UserDB ${CMAKE_BINARY_DIR}/UserDBTests --log_sink=UserDBTests.log --report_sink=UserDBTests.report)

add_executable(StringTests
        StringUtils.cpp
        StringTests.cpp
)

if(NOT DO_STATIC_LINK)
  target_compile_definitions(StringTests PUBLIC BOOST_TEST_DYN_LINK=1)
endif()

target_link_libraries(StringTests ${Boost_LIBRARIES})

add_test(String ${CMAKE_BINARY_DIR}/StringTests --log_sink=StringTests.log --report_sink=StringTests.report)

add_executable(EventProcessorTests
        auoms_version.h
        EventProcessorTests.cpp
        Event.cpp
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
        CmdlineRedactor.cpp
        FileUtils.cpp
)

if(NOT DO_STATIC_LINK)
  target_compile_definitions(EventProcessorTests PUBLIC BOOST_TEST_DYN_LINK=1)
endif()

target_link_libraries(EventProcessorTests ${Boost_LIBRARIES}
        ${RE2_LIBS}
        dl
        pthread
        rt
)

add_test(EventProcessor ${CMAKE_BINARY_DIR}/EventProcessorTests --log_sink=EventProcessorTests.log --report_sink=EventProcessorTests.report)

add_executable(ProcessInfoTests
    auoms_version.h
    ProcessInfoTests.cpp
    Event.cpp
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
    ExecveConverter.cpp
)

target_link_libraries(ProcessInfoTests ${Boost_LIBRARIES}
    ${RE2_LIBS}
    dl
    pthread
    rt
)

if(NOT DO_STATIC_LINK)
  target_compile_definitions(ProcessInfoTests PUBLIC BOOST_TEST_DYN_LINK=1)
endif()

add_test(NAME ProcessInfoTests COMMAND ProcessInfoTests)

add_executable(ProcessTreeTests
        auoms_version.h
        ProcessTreeTests.cpp
        Event.cpp
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
        ExecveConverter.cpp
)

if(NOT DO_STATIC_LINK)
  target_compile_definitions(ProcessTreeTests PUBLIC BOOST_TEST_DYN_LINK=1)
endif()

target_link_libraries(ProcessTreeTests ${Boost_LIBRARIES}
        ${RE2_LIBS}
        dl
        pthread
        rt
)

add_test(EventProcessor ${CMAKE_BINARY_DIR}/ProcessTreeTests --log_sink=ProcessTreeTests.log --report_sink=ProcessTreeTests.report)

add_executable(ExecveConverterTests
        auoms_version.h
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

if(NOT DO_STATIC_LINK)
  target_compile_definitions(ExecveConverterTests PUBLIC BOOST_TEST_DYN_LINK=1)
endif()

target_link_libraries(ExecveConverterTests ${Boost_LIBRARIES}
        dl
        pthread
        rt
)

add_test(ExecveConverter ${CMAKE_BINARY_DIR}/ExecveConverterTests --log_sink=ExecveConverterTests.log --report_sink=ExecveConverterTests.report)

add_executable(OMSEventWriterTests
        auoms_version.h
        OMSEventWriterTests.cpp
        OMSEventWriter.cpp
        EventWriterConfig.cpp
        Event.cpp
        AbstractEventWriter.cpp
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

if(NOT DO_STATIC_LINK)
  target_compile_definitions(OMSEventWriterTests PUBLIC BOOST_TEST_DYN_LINK=1)
endif()

target_link_libraries(OMSEventWriterTests ${Boost_LIBRARIES}
        ${RE2_LIBS}
        pthread
)

add_test(OMSEventWriter ${CMAKE_BINARY_DIR}/OMSEventWriterTests --log_sink=OMSEventWriterTests.log --report_sink=OMSEventWriterTests.report)

add_executable(FluentEventWriterTests
        auoms_version.h
        FluentEventWriterTests.cpp
        FluentEventWriter.cpp
        Event.cpp
        AbstractEventWriter.cpp
        Logger.cpp
        StringUtils.cpp
        TestEventData.cpp
        ExecveConverter.cpp
        CmdlineRedactor.cpp
        FileUtils.cpp
        Config.cpp
)

if(NOT DO_STATIC_LINK)
  target_compile_definitions(FluentEventWriterTests PUBLIC BOOST_TEST_DYN_LINK=1)
endif()

target_link_libraries(FluentEventWriterTests ${Boost_LIBRARIES}
        ${RE2_LIBS}
        pthread
)

add_test(FluentEventWriter ${CMAKE_BINARY_DIR}/FluentEventWriterTests --log_sink=FluentEventWriterTests.log --report_sink=FluentEventWriterTests.report)

add_executable(OutputInputTests
        auoms_version.h
        OutputInputTests.cpp
        TempDir.cpp
        Event.cpp
        Logger.cpp
        Config.cpp
        StringUtils.cpp
        RunBase.cpp
        Output.cpp
        Inputs.cpp
        Input.cpp
        OperationalStatus.cpp
        IO.cpp
        PriorityQueue.cpp
        UnixDomainListener.cpp
        UnixDomainWriter.cpp
        TranslateRecordType.cpp
        Signals.cpp
        FileUtils.cpp
        AuditRules.cpp
        KernelInfo.cpp
        TranslateArch.cpp
        TranslateErrno.cpp
        TranslateField.cpp
        TranslateSyscall.cpp
        UserDB.cpp
        Version.cpp
        EventMatcher.cpp
        EventAggregator.cpp
)

if(NOT DO_STATIC_LINK)
  target_compile_definitions(OutputInputTests PUBLIC BOOST_TEST_DYN_LINK=1)
endif()

target_link_libraries(OutputInputTests
        ${RE2_LIBS}
        ${Boost_LIBRARIES}
        pthread
)

add_test(OutputInputTests ${CMAKE_BINARY_DIR}/OutputInputTests --log_sink=OutputInputTests.log --report_sink=OutputInputTests.report)


add_executable(CmdlineRedactorTests
        CmdlineRedactorTests.cpp
        CmdlineRedactor.cpp
        Config.cpp
        Logger.cpp
        FileUtils.cpp
        StringUtils.cpp
        TempDir.cpp
)

if(NOT DO_STATIC_LINK)
  target_compile_definitions(CmdlineRedactorTests PUBLIC BOOST_TEST_DYN_LINK=1)
endif()

target_link_libraries(CmdlineRedactorTests
        ${RE2_LIBS}
        ${Boost_LIBRARIES}
        pthread
)

add_test(CmdlineRedactorTests ${CMAKE_BINARY_DIR}/CmdlineRedactorTests --log_sink=CmdlineRedactorTests.log --report_sink=CmdlineRedactorTests.report)


add_executable(EventMatcherTests
        auoms_version.h
        EventMatcherTests.cpp
        EventMatcher.cpp
        Event.cpp
        TranslateRecordType.cpp
        StringUtils.cpp
        TestEventData.cpp
)

if(NOT DO_STATIC_LINK)
  target_compile_definitions(EventMatcherTests PUBLIC BOOST_TEST_DYN_LINK=1)
endif()

target_link_libraries(EventMatcherTests
        ${RE2_LIBS}
        ${Boost_LIBRARIES}
        pthread
)

add_test(EventMatcherTests ${CMAKE_BINARY_DIR}/EventMatcherTests --log_sink=EventMatcherTests.log --report_sink=EventMatcherTests.report)

add_executable(EventAggregatorTests
        auoms_version.h
        EventAggregatorTests.cpp
        EventAggregator.cpp
        EventMatcher.cpp
        Event.cpp
        TranslateRecordType.cpp
        StringUtils.cpp
        TestEventData.cpp
        TempFile.cpp
)

if(NOT DO_STATIC_LINK)
  target_compile_definitions(EventAggregatorTests PUBLIC BOOST_TEST_DYN_LINK=1)
endif()

target_link_libraries(EventAggregatorTests
        ${RE2_LIBS}
        ${Boost_LIBRARIES}
        pthread
)

add_test(EventAggregatorTests ${CMAKE_BINARY_DIR}/EventAggregatorTests --log_sink=EventAggregatorTests.log --report_sink=EventAggregatorTests.report)
