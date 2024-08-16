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

CheckDownloadFile() {
  HASH=$1
  URL=$2
  DEST=$3

  if [ -e $DEST ]; then
    echo "$HASH  $DEST" | sha256sum -c -
    if [ $? -eq 0 ]; then
      return 0
    fi
  fi


  echo "($DEST) is missing (or out of date). Downloading..." >& 2
  wget -q $URL -O $DEST
  if [ $? -ne 0 ]; then
    echo "Failed to download $URL" >& 2
    return 1
  fi

  echo "$HASH  $DEST" | sha256sum -c -
  if [ $? -ne 0 ]; then
    echo "($DEST) does not match the hash!" >& 2
    return 1
  fi
}

ShowUsage()
{
  cat << EOF
  Error: $1

  Usage: $0 -d <dest dir>

    -d <dest dir>
EOF
    exit 1
}

while (( "$#" )); do
  if [ "$1" == "-d" ]; then
    shift
    DestDir=$1
  else
    ShowUsage "unsupported argument '$1'"
  fi
    shift
done

if [ -z "$DestDir" ]; then
  ShowUsage "Missing destination dir"
fi

if [ ! -d $DestDir ]; then
  echo "'$DestDir' is missing or not a directory"
  exit 1
fi

CheckDownloadFile c3711ed2b3c76a5565ee9f0128bb4ec6753dbcc23450b713842df8f236d08666 https://github.com/Tencent/rapidjson/archive/v1.0.2.tar.gz ${DestDir}/rapidjson-1.0.2.tar.gz
if [ $? -ne 0 ]; then
  exit 1
fi

CheckDownloadFile 9f3860bc014355dbdf6519ffb78d54d120bb8d134dcb4eba35eb5103c1ac3cd1 https://github.com/msgpack/msgpack-c/archive/cpp-2.0.0.zip ${DestDir}/msgpack-c-cpp-2.0.0.zip
if [ $? -ne 0 ]; then
  exit 1
fi

CheckDownloadFile b7a29e40083005d280136205a925a49a1cc2b22df7c2a5e3764c35d1c70f4441 https://github.com/google/re2/archive/2020-11-01.zip ${DestDir}/re2-2020-11-01.zip
if [ $? -ne 0 ]; then
  exit 1
fi

# CheckDownloadFile 7861d544190f938cac1b242624d78c96fe2ebbc7b72f86166e88b50451c6fa58 https://github.com/systemd/systemd/archive/v256.4.tar.gz ${DestDir}/systemd-256.4.tar.gz
# if [ $? -ne 0 ]; then
#   exit 1
# fi
