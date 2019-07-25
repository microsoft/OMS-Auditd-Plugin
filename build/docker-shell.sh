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

cd $(dirname $0)/..
SRC_ROOT=$(pwd)
cd ..
BIND_MOUNT_DIR=$(pwd)

if [ ! -e $SRC_ROOT/build/configure ]; then
    echo "The bind mount appears to be invalid: could not find $SRC_ROOT/build/configure"
    exit 1
fi

if [ ! -e $BIND_MOUNT_DIR/pal/installer/InstallBuilder/installbuilder.py ]; then
    echo "The bind mount appears to be invalid: could not find $BIND_MOUNT_DIR/pal/installer/InstallBuilder/installbuilder.py"
    exit 1
fi

BUILD_UID=$(stat -c '%u' $BIND_MOUNT_DIR)
BUILD_GID=$(stat -c '%g' $BIND_MOUNT_DIR)

grep '^build' /etc/passwd >/dev/null
if [ $BUILD_UID -ne 0 -a $? -ne 0 ]; then
    groupadd -g $BUILD_GID build
    useradd -u $BUILD_UID -g build -d /var/build -m -s /bin/bash build
fi

exec sudo -u build -i
