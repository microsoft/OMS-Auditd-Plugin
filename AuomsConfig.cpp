/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "AuomsConfig.h"
#include "CPULimits.h"

std::string AuomsConfig::KEY_OUTCONF_DIR = "outconf_dir";
std::string AuomsConfig::KEY_RULES_DIR = "rules_dir";
std::string AuomsConfig::KEY_REDACT_DIR = "redact_dir";
std::string AuomsConfig::KEY_DATA_DIR = "data_dir";
std::string AuomsConfig::KEY_RUN_DIR = "run_dir";
std::string AuomsConfig::KEY_AUDITD_PATH = "auditd_path";
std::string AuomsConfig::KEY_COLLECTOR_PATH = "collector_path";
std::string AuomsConfig::KEY_COLLECTOR_CONFIG_PATH = "collector_config_path";
std::string AuomsConfig::KEY_BACKLOG_LIMIT = "backlog_limit";
std::string AuomsConfig::KEY_BACKLOG_WAIT_TIME = "backlog_wait_time";
std::string AuomsConfig::KEY_INPUT_SOCKET_PATH = "input_socket_path";
std::string AuomsConfig::KEY_STATUS_SOCKET_PATH = "status_socket_path";
std::string AuomsConfig::KEY_SAVE_DIR = "save_dir";
std::string AuomsConfig::KEY_QUEUE_DIR = "queue_dir";
std::string AuomsConfig::KEY_RSS_LIMIT = "rss_limit";
std::string AuomsConfig::KEY_RSS_PCT_LIMIT = "rss_pct_limit";
std::string AuomsConfig::KEY_VIRT_LIMIT = "virt_limit";
std::string AuomsConfig::KEY_NUM_PRIORITIES = "queue_num_priorities";
std::string AuomsConfig::KEY_MAX_FILE_DATA_SIZE = "queue_max_file_data_size";
std::string AuomsConfig::KEY_MAX_UNSAVED_FILES = "queue_max_unsaved_files";
std::string AuomsConfig::KEY_MAX_FS_BYTES = "queue_max_fs_bytes";
std::string AuomsConfig::KEY_MAX_FS_PCT = "queue_max_fs_pct";
std::string AuomsConfig::KEY_MIN_FS_FREE_PCT = "queue_min_fs_free_pct";
std::string AuomsConfig::KEY_SAVE_DELAY = "queue_save_delay";
std::string AuomsConfig::KEY_LOCK_FILE = "lock_file";
std::string AuomsConfig::KEY_USE_SYSLOG = "use_syslog";
std::string AuomsConfig::KEY_DISABLE_CGROUPS = "disable_cgroups";
std::string AuomsConfig::KEY_DISABLE_EVENT_FILTERING = "disable_event_filtering";
std::string AuomsConfig::KEY_DEFAULT_EVENT_PRIORITY = "default_event_priority";
std::string AuomsConfig::KEY_PROC_PATH = "proc_path";

std::unique_ptr<AuomsConfig> AuomsConfig::_instance;
std::once_flag AuomsConfig::_initFlag;

void
AuomsConfig::Load(const std::string& path) {
    Config::Load(path);

    if (HasKey(KEY_OUTCONF_DIR)) {
        _outconf_dir = GetString(KEY_OUTCONF_DIR);
    }
    if (HasKey(KEY_RULES_DIR)) {
        _rules_dir = GetString(KEY_RULES_DIR);
    }
    if (HasKey(KEY_REDACT_DIR)) {
        _redact_dir = GetString(KEY_REDACT_DIR);
    }
    if (HasKey(KEY_DATA_DIR)) {
        _data_dir = GetString(KEY_DATA_DIR);
    }
    if (HasKey(KEY_PROC_PATH)) {
        _proc_path = GetString(KEY_PROC_PATH);
    }
    if (HasKey(KEY_RUN_DIR)) {
        _run_dir = GetString(KEY_RUN_DIR);
    }
    if (HasKey(KEY_AUDITD_PATH)) {
        _auditd_path = GetString(KEY_AUDITD_PATH);
    }
    if (HasKey(KEY_COLLECTOR_PATH)) {
        _collector_path = GetString(KEY_COLLECTOR_PATH);
    }
    if (HasKey(KEY_COLLECTOR_CONFIG_PATH)) {
        _collector_config_path = GetString(KEY_COLLECTOR_CONFIG_PATH);
    }
    if (HasKey(KEY_BACKLOG_LIMIT)) {
        _backlog_limit = static_cast<uint32_t>(GetUint64(KEY_BACKLOG_LIMIT));
    }
    if (HasKey(KEY_BACKLOG_WAIT_TIME)) {
        _backlog_wait_time = static_cast<uint32_t>(
                                GetUint64(KEY_BACKLOG_WAIT_TIME)
                                );
    }
    if (HasKey(KEY_INPUT_SOCKET_PATH)) {
        _input_socket_path = GetString(KEY_INPUT_SOCKET_PATH);
    } else {
        _input_socket_path = _run_dir + "/input.socket";
    }
    if (HasKey(KEY_STATUS_SOCKET_PATH)) {
        _status_socket_path = GetString(KEY_STATUS_SOCKET_PATH);
    } else {
        _status_socket_path = _run_dir + "/status.socket";
    }
    if (HasKey(KEY_SAVE_DIR)) {
        _save_dir = GetString(KEY_SAVE_DIR);
    } else {
        _save_dir = _data_dir + "/save";
    }
    if (HasKey(KEY_QUEUE_DIR)) {
        _queue_dir = GetString(KEY_QUEUE_DIR);
    } else {
        _queue_dir = _data_dir + "/queue";
    }
    if (HasKey(KEY_RSS_LIMIT)) {
        _rss_limit = GetUint64(KEY_RSS_LIMIT);
    }
    if (HasKey(KEY_RSS_PCT_LIMIT)) {
        _rss_pct_limit = GetDouble(KEY_RSS_PCT_LIMIT);
    }
    if (HasKey(KEY_VIRT_LIMIT)) {
        _virt_limit = GetUint64(KEY_VIRT_LIMIT);
    }
    if (HasKey(KEY_NUM_PRIORITIES)) {
        _num_priorities = GetUint64(KEY_NUM_PRIORITIES);
    }
    if (HasKey(KEY_MAX_FILE_DATA_SIZE)) {
        _max_file_data_size = GetUint64(KEY_MAX_FILE_DATA_SIZE);
    }
    if (HasKey(KEY_MAX_UNSAVED_FILES)) {
        _max_unsaved_files = GetUint64(KEY_MAX_UNSAVED_FILES);
    }
    if (HasKey(KEY_MAX_FS_BYTES)) {
        _max_fs_bytes = GetUint64(KEY_MAX_FS_BYTES);
    }
    if (HasKey(KEY_MAX_FS_PCT)) {
        _max_fs_pct = GetDouble(KEY_MAX_FS_PCT);
    }
    if (HasKey(KEY_MIN_FS_FREE_PCT)) {
        _min_fs_free_pct = GetDouble(KEY_MIN_FS_FREE_PCT);
    }
    if (HasKey(KEY_SAVE_DELAY)) {
        _save_delay = GetUint64(KEY_SAVE_DELAY);
    }
    if (HasKey(KEY_LOCK_FILE)) {
        _lock_file = GetString(KEY_LOCK_FILE);
    } else {
        _lock_file = _data_dir + "/auoms.lock";
    }
    if (HasKey(KEY_USE_SYSLOG)) {
        _useSyslog = GetBool(KEY_USE_SYSLOG);
    }
    if (HasKey(KEY_DISABLE_CGROUPS)) {
        _disableCGroups = GetBool(KEY_DISABLE_CGROUPS);
    }
    // Set cgroup defaults
    if (!HasKey(CPU_SOFT_LIMIT_NAME)) {
        SetString(CPU_SOFT_LIMIT_NAME, "5");
    }
    if (!HasKey(CPU_HARD_LIMIT_NAME)) {
        SetString(CPU_HARD_LIMIT_NAME, "25");
    }
    if (HasKey(KEY_DISABLE_EVENT_FILTERING)) {
        _disableEventFiltering = GetBool(KEY_DISABLE_EVENT_FILTERING);
    }
    // Set EventPrioritizer defaults
    if (!HasKey("event_priority_by_syscall")) {
        SetString(
            "event_priority_by_syscall",
            R"json({"execve":2,"execveat":2,"*":3})json"
        );
    }
    if (!HasKey("event_priority_by_record_type")) {
        SetString(
            "event_priority_by_record_type",
            R"json({"AUOMS_EXECVE":2,"AUOMS_SYSCALL":3,"AUOMS_PROCESS_INVENTORY":1})json"
        );
    }
    if (!HasKey("event_priority_by_record_type_category")) {
        SetString(
            "event_priority_by_record_type_category",
            R"json({"AUOMS_MSG":0, "USER_MSG":1,"SELINUX":1,"APPARMOR":1})json"
        );
    }
    if (HasKey(KEY_DEFAULT_EVENT_PRIORITY)) {
        _defaultEventPriority = static_cast<uint16_t>(
                                GetUint64(KEY_DEFAULT_EVENT_PRIORITY)
                            );
    }
    if (_defaultEventPriority > _num_priorities-1) {
        _defaultEventPriority = _num_priorities-1;
    }
}

bool
AuomsConfig::IsNetlinkOnly() const {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _isNetlinkOnly;
}

void
AuomsConfig::SetNetlinkOnly(const bool& value) {
    std::unique_lock<std::shared_mutex> lock(_mutex);
    _isNetlinkOnly = value;
}

const std::string&
AuomsConfig::GetQueueDir() const {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _queue_dir;
}

bool
AuomsConfig::UseSyslog() const {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _useSyslog;
}

int
AuomsConfig::GetDefaultEventPriority() const {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _defaultEventPriority;
}

const std::string&
AuomsConfig::GetSaveDirectory() const {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _save_dir;
}

const std::string&
AuomsConfig::GetLockFile() const {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _lock_file; 
}

bool
AuomsConfig::DisableCGroups() const {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _disableCGroups;
}

int
AuomsConfig::GetNumberOfEventPriorities() const {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _num_priorities; 
}

size_t
AuomsConfig::GetMaxFileDataSize() const {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _max_file_data_size;
}

size_t
AuomsConfig::GetMaxUnsavedFiles() const {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _max_unsaved_files;
}

size_t
AuomsConfig::GetMaxFsBytes() const {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _max_fs_bytes;
}

double
AuomsConfig::GetMaxFsPercentage() const {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _max_fs_pct;
}

double
AuomsConfig::GetMinFsFreePercentage() const {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _min_fs_free_pct;
}

const std::string&
AuomsConfig::GetStatusSocketPath() const {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _status_socket_path;
}

const std::string&
AuomsConfig::GetRedactDir() const {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _redact_dir;
}

const std::string&
AuomsConfig::GetInputSocketPath() const {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _input_socket_path;
}

uint64_t
AuomsConfig::GetRSSLimit() const {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _rss_limit;
}

uint64_t
AuomsConfig::GetVirtLimit() const {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _virt_limit;
}

double
AuomsConfig::GetRSSPercentageLimit() const {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _rss_pct_limit;
}

const std::string&
AuomsConfig::GetAuditdPath() const {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _auditd_path;
}

const std::string&
AuomsConfig::GetCollectorPath() const {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _collector_path;
}

const std::string&
AuomsConfig::GetCollectorConfigPath() const {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _collector_config_path;
}

const std::string&
AuomsConfig::GetRulesDir() const {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _rules_dir; 
}

uint32_t
AuomsConfig::GetBacklogLimit() const {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _backlog_limit;
}

uint32_t
AuomsConfig::GetBacklogWaitTime() const {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _backlog_wait_time;
}

const std::string&
AuomsConfig::GetOutconfDir() const {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _outconf_dir;  
}

const std::string&
AuomsConfig::GetProcPath() const {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _proc_path;
}

long
AuomsConfig::GetSaveDelay() const {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _save_delay;
}

bool
AuomsConfig::DisableEventFiltering() const {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _disableEventFiltering;
}