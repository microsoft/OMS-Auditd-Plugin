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

find $SRC_ROOT/artifacts -type d
ls -FlaR $SRC_ROOT/artifacts

set -e -v
ln -s $SRC_ROOT/artifacts/drop\ Sign $SRC_ROOT/artifacts/drop-Sign
set +e +v

PACKAGE_DIR=$SRC_ROOT/artifacts/drop-Sign/build
TARGET_DIR=$SRC_ROOT/target

RPM_PKG=$(ls ${PACKAGE_DIR}/auoms-[0-9]*.rpm)

if [ -z "$RPM_PKG" ] || [ ! -e $RPM_PKG ]; then
    echo "Failed to find package"
    exit 1
fi

PACKAGE_PREFIX=$(basename -s .rpm $RPM_PKG)

if [ ! -e ${TARGET_DIR} ]; then
    mkdir -p ${TARGET_DIR}
fi

if [ -e /tmp/installer_tmp ]; then
    rm -rf /tmp/installer_tmp
fi

mkdir /tmp/installer_tmp

cd ${PACKAGE_DIR}

cp $RPM_PKG /tmp
if [ $? -ne 0 ]; then
    echo "Failed to copy rpm file"
fi

tar cvf /tmp/${PACKAGE_PREFIX}.tar ${PACKAGE_PREFIX}.{deb,rpm}
if [ $? -ne 0 ]; then
    echo "Failed to create tar file"
fi

cd $SRC_ROOT/build
../installer/bundle/create_bundle.sh ${TARGET_DIR} /tmp ${PACKAGE_PREFIX}.tar
if [ $? -ne 0 ]; then
    echo "Failed to create bundle"
fi

if [ ! -e ${TARGET_DIR}/${PACKAGE_PREFIX}.sh ]; then
    echo "Failed to create bundle"
    exit 1
fi
