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

cd $(dirname $0)/../..
ROOT=$(pwd)

if [ ! -e ${ROOT}/rapidjson-1.0.2.tar.gz ]; then
    echo "rapidjson 1.0.2 tar file (${ROOT}/v1.0.2.tar.gz) is missing. Downloading..." >& 2
    wget -O ${ROOT}/rapidjson-1.0.2.tar.gz https://github.com/Tencent/rapidjson/archive/v1.0.2.tar.gz >& 2
fi

echo "c3711ed2b3c76a5565ee9f0128bb4ec6753dbcc23450b713842df8f236d08666  ${ROOT}/rapidjson-1.0.2.tar.gz" | sha256sum -c -
if [ $? -ne 0 ]; then
    echo "Download of ${ROOT}/rapidjson-1.0.2.tar.gz failed or file is corrupted!" >& 2
    exit 1
fi

if [ ! -e ${ROOT}/msgpack-c-cpp-2.0.0.zip ]; then
    echo "MsgPack cpp 2.0.0 zip file (${ROOT}/cpp-2.0.0.zip) is missing. Downloading..." >& 2
    wget -O ${ROOT}/msgpack-c-cpp-2.0.0.zip https://github.com/msgpack/msgpack-c/archive/cpp-2.0.0.zip >& 2
fi

echo "9f3860bc014355dbdf6519ffb78d54d120bb8d134dcb4eba35eb5103c1ac3cd1  ${ROOT}/msgpack-c-cpp-2.0.0.zip" | sha256sum -c -
if [ $? -ne 0 ]; then
    echo "Download of ${ROOT}/msgpack-c-cpp-2.0.0.zip failed or file is corrupted!" >& 2
    exit 1
fi
