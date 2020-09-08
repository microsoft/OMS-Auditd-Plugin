/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_ENV_CONFIG_H
#define AUOMS_ENV_CONFIG_H

#ifndef AUOMS_RUN_DIR
#define AUOMS_RUN_DIR "/var/run/auoms"
#endif

#ifndef AUOMS_DATA_DIR
#define AUOMS_DATA_DIR "/var/opt/microsoft/auoms"
#endif

#ifndef AUOMS_RULES_DIR
#define AUOMS_RULES_DIR "/etc/opt/microsoft/auoms/rules.d"
#endif

#ifndef AUOMS_OUTCONF_DIR
#define AUOMS_OUTCONF_DIR "/etc/opt/microsoft/auoms/outconf.d"
#endif

#ifndef AUOMSCOLLECT_EXE
#define AUOMSCOLLECT_EXE "/opt/microsoft/auoms/bin/auomscollect"
#endif

#ifndef AUOMS_CONF
#define AUOMS_CONF "/etc/opt/microsoft/auoms/auoms.conf"
#endif

#ifndef AUOMSCOLLECT_CONF
#define AUOMSCOLLECT_CONF "/etc/opt/microsoft/auoms/auomscollect.conf"
#endif

#ifndef AUDITD_BIN
#define AUDITD_BIN "/sbin/auditd"
#endif

#ifndef AUOMS_PLUGIN_FILE
#define AUOMS_PLUGIN_FILE "/etc/audisp/plugins.d/auoms.conf"
#endif

#ifndef SYSTEMD_SERVICE_FILE
#define SYSTEMD_SERVICE_FILE "/opt/microsoft/auoms/auoms.service"
#endif

#ifndef SYSTEMCTL_PATH
#define SYSTEMCTL_PATH "/bin/systemctl"
#endif

#ifndef CHKCONFIG_PATH
#define CHKCONFIG_PATH "/sbin/chkconfig"
#endif

#ifndef UPDATE_RC_PATH
#define UPDATE_RC_PATH "/usr/sbin/update-rc.d"
#endif

#endif //AUOMS_ENV_CONFIG_H
