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

ROOT=$(cd $(dirname $0) && pwd)

DEPS_DIR=$ROOT/build-deps

if [ ! -e $DEPS_DIR ]; then
  mkdir $DEPS_DIR
fi

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

while IFS='' read -r line || [[ -n "${line}" ]]; do
  read -a fields <<< $line
  hash=${fields[0]}
  url=${fields[1]}
  file=$(basename $url)
  CheckDownloadFile $hash $url $DEPS_DIR/$file
  if [ $? -ne 0 ]; then
    exit 1
  fi
done < $ROOT/build_deps.list
