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
TOP_DIR=$(pwd)

if [ ! -e $SRC_ROOT/build/configure ]; then
    echo "The bind mount appears to be invalid: could not find $SRC_ROOT/build/configure"
    exit 1
fi

if [ ! -e TOP_DIR/pal/installer/InstallBuilder/installbuilder.py ]; then
    echo "Could not find $TOP_DIR/pal/installer/InstallBuilder/installbuilder.py"
    exit 1
fi

cd $SRC_ROOT/build
./configure --enable-ulinux
if [ $? -ne 0 ]; then
    exit $?
fi

. /opt/rh/devtoolset-7/enable
if [ $? -ne 0 ]; then
    exit $?
fi

make clean
if [ $? -ne 0 ]; then
    exit $?
fi

make packages
