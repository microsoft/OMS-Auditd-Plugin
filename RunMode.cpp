/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "RunMode.h"

#include "Config.h"

bool RunMode::_configured = false;
std::mutex RunMode::_mutex;

#define KEY_CONTAINER_MODE_ENABLED "container_mode.enabled"
#define KEY_CONTAINER_HOST_MOUNT_PATH "container_mode.host_mount_path"

void
RunMode::Configure() {
    std::lock_guard<std::mutex> lock(_mutex);
    if (!_configured) {
        Config config;
        bool containerMode = false;
        std::string hostMountPath;
        if (config.HasKey(KEY_CONTAINER_MODE_ENABLED)) {
            containerMode = config.GetBool(KEY_CONTAINER_MODE_ENABLED);
            if (containerMode) {
                if (config.HasKey(KEY_CONTAINER_HOST_MOUNT_PATH)) {
                    hostMountPath = config.GetString(KEY_CONTAINER_HOST_MOUNT_PATH);
                }
            }
        }
        _executeInContainer = containerMode;
        _hostMountPath = hostMountPath;
        _configured = true;
    }
}
