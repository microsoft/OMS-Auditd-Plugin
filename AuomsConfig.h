/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "Config.h"
#include "env_config.h"

#include <memory>
#include <shared_mutex>
#include <mutex>

class AuomsConfig : public Config {
public:
    // Delete copy constructor and assignment operator
    AuomsConfig(const AuomsConfig&) = delete;
    AuomsConfig& operator=(const AuomsConfig&) = delete;

    static AuomsConfig& GetInstance() {
        std::call_once(_initFlag, []() {
            _instance.reset(new AuomsConfig());
        });
        return *_instance;
    }

    virtual void Load(const std::string& path);

    bool IsNetlinkOnly() const;
    void SetNetlinkOnly(const bool& value);

    const std::string& GetQueueDir() const;

    bool UseSyslog() const;

    int GetDefaultEventPriority() const;

    const std::string& GetSaveDirectory() const;

    const std::string& GetLockFile() const;

    bool DisableCGroups() const;

    int GetNumberOfEventPriorities() const;
    size_t GetMaxFileDataSize() const;
    size_t GetMaxUnsavedFiles() const;
    size_t GetMaxFsBytes() const;
    double GetMaxFsPercentage() const;
    double GetMinFsFreePercentage() const;

    const std::string& GetInputSocketPath() const;
    const std::string& GetStatusSocketPath() const;
    const std::string& GetRedactDir() const;
    const std::string& GetAuditdPath() const;
    const std::string& GetCollectorPath() const;
    const std::string& GetCollectorConfigPath() const;
    const std::string& GetRulesDir() const;
    const std::string& GetOutconfDir() const;
    const std::string& GetProcPath() const;

    uint64_t GetRSSLimit() const;
    uint64_t GetVirtLimit() const;
    double GetRSSPercentageLimit() const;

    uint32_t GetBacklogLimit() const;
    uint32_t GetBacklogWaitTime() const;

    long GetSaveDelay() const;

    bool DisableEventFiltering() const;

private:
    AuomsConfig() = default;

    mutable std::shared_mutex _mutex;

    std::string _auditd_path = AUDITD_BIN;
    std::string _collector_path = AUOMSCOLLECT_EXE;
    std::string _collector_config_path = "";

    std::string _outconf_dir = AUOMS_OUTCONF_DIR;
    std::string _rules_dir = AUOMS_RULES_DIR;
    std::string _redact_dir = AUOMS_REDACT_DIR;
    std::string _data_dir = AUOMS_DATA_DIR;
    std::string _proc_path = "/proc";
    std::string _run_dir = AUOMS_RUN_DIR;
    std::string _input_socket_path;
    std::string _status_socket_path;
    std::string _save_dir;
    std::string _queue_dir;
    std::string _lock_file;

    uint32_t _backlog_limit = 10240;
    uint32_t _backlog_wait_time = 1;

    uint64_t _rss_limit = 1024L*1024L*1024L;
    uint64_t _virt_limit = 4096L*1024L*1024L;
    double _rss_pct_limit = 5;

    int _num_priorities = 8;
    size_t _max_file_data_size = 1024*1024;
    size_t _max_unsaved_files = 128;
    size_t _max_fs_bytes = 1024*1024*1024;
    double _max_fs_pct = 10;
    double _min_fs_free_pct = 5;
    long _save_delay = 250;

    bool _isNetlinkOnly = false;
    bool _useSyslog = true;
    bool _disableCGroups = false;
    bool _disableEventFiltering = false;

    int _defaultEventPriority = 4;

    static std::unique_ptr<AuomsConfig> _instance;
    static std::once_flag _initFlag;

    static std::string KEY_OUTCONF_DIR;
    static std::string KEY_RULES_DIR;
    static std::string KEY_REDACT_DIR;
    static std::string KEY_DATA_DIR;
    static std::string KEY_RUN_DIR;
    static std::string KEY_AUDITD_PATH;
    static std::string KEY_COLLECTOR_PATH;
    static std::string KEY_COLLECTOR_CONFIG_PATH;
    static std::string KEY_BACKLOG_LIMIT;
    static std::string KEY_BACKLOG_WAIT_TIME;
    static std::string KEY_INPUT_SOCKET_PATH;
    static std::string KEY_STATUS_SOCKET_PATH;
    static std::string KEY_SAVE_DIR;
    static std::string KEY_QUEUE_DIR;
    static std::string KEY_RSS_LIMIT;
    static std::string KEY_RSS_PCT_LIMIT;
    static std::string KEY_VIRT_LIMIT;
    static std::string KEY_NUM_PRIORITIES;
    static std::string KEY_MAX_FILE_DATA_SIZE;
    static std::string KEY_MAX_UNSAVED_FILES;
    static std::string KEY_MAX_FS_BYTES;
    static std::string KEY_MAX_FS_PCT;
    static std::string KEY_MIN_FS_FREE_PCT;
    static std::string KEY_SAVE_DELAY;
    static std::string KEY_LOCK_FILE;
    static std::string KEY_USE_SYSLOG;
    static std::string KEY_DISABLE_CGROUPS;
    static std::string KEY_DISABLE_EVENT_FILTERING;
    static std::string KEY_DEFAULT_EVENT_PRIORITY;
    static std::string KEY_PROC_PATH;
};