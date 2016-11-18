#!/bin/bash

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


ulinux_detect_installer()
{
    INSTALLER=

    # If DPKG lives here, assume we use that. Otherwise we use RPM.
    which dpkg > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        INSTALLER=DPKG
    else
        INSTALLER=RPM
    fi
}

# $1 - The name of the package to check as to whether it's installed
check_if_pkg_is_installed() {
    if [ "$INSTALLER" = "DPKG" ]; then
        dpkg -s $1 2> /dev/null | grep Status | grep " installed" 1> /dev/null
    else
        rpm -q $1 2> /dev/null 1> /dev/null
    fi

    return $?
}

ISSUE_WARNING=0

echo "Checking if Auditd and libauparse are installed..." 1>&2
if [ "$INSTALLER" = "DPKG" ]; then
    # On debian based systems, the auditd package depends on the libauparse0 package
    check_if_pkg_is_installed auditd
    if [ $? -ne 0 ]; then
        echo "  auditd package isn't installed" 1>&2
        ISSUE_WARNING=1
    fi
else
    check_if_pkg_is_installed audit
    if [ $? -ne 0 ]; then
        echo "  audit package isn't installed" 1>&2
        ISSUE_WARNING=1
    else
        check_if_pkg_is_installed audit-libs
        if [ $? -ne 0 ]; then
            echo "  audit-libs package isn't installed" 1>&2
            ISSUE_WARNING=1
        fi
    fi
fi

if [ $ISSUE_WARNING -ne 0 ]; then
    echo "  Because neccessary dependencies are not installed, the auoms auditd plugin cannot be installed." 1>&2
    exit 1
fi