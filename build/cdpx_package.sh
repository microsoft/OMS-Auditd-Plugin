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

find ${CDP_TEMP_PRIOR_DROP_FOLDER_CONTAINER_PATH} -type d
ls -FlaR ${CDP_TEMP_PRIOR_DROP_FOLDER_CONTAINER_PATH}

PACKAGE_DIR=${CDP_TEMP_PRIOR_DROP_FOLDER_CONTAINER_PATH}/current/drop/Sign
TARGET_DIR=target

DEP_PKG=$(ls ${PACAKGE_DIR}/auoms-*.deb)

if [ -z "$DEP_PKG" ] || [ ! -e $DEP_PKG ]; then
    echo "Failed to find package"
    exit 1
fi

PACKAGE_PREFIX=$(basename -s .deb $DEB_PKG)

mkdir -p ${TARGET_DIR}

cd PACKAGE_DIR
tar cvf /tmp/$(OUTPUT_PACKAGE_PREFIX).tar $(OUTPUT_PACKAGE_PREFIX).{deb,rpm}

cd $SRC_ROOT
installer/bundle/create_bundle.sh $(TARGET_DIR) /tmp /tmp/$(OUTPUT_PACKAGE_PREFIX).tar
