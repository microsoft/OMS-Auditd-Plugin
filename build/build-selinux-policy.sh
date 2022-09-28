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

ShowUsage()
{
  cat << EOF
  Error: $1

  Usage: $0 -d <dest dir> -w <work dir> [ -s <source dir> ]

    -d  <dest dir>     - Where built packages will be placed
    -w  <work dir>     - Directory where work dir will be placed
    -s  <source dir>   - Root of source code

EOF
    exit 1
}

Bail()
{
  echo "Error: $1"
  exit 1
}

while (( "$#" )); do
  if [ "$1" == "-d" ]; then
    shift
    DestDir=$1
  elif [ "$1" == "-w" ]; then
    shift
    WorkDirRoot=$1
  elif [ "$1" == "-s" ]; then
    shift
    SourceDir=$1
  else
    ShowUsage "unsupported argument '$1'"
  fi
  shift
done

if [ -z "$DestDir" ]; then
  ShowUsage "Missing destination dir"
fi

if [ -z "$WorkDirRoot" ]; then
  ShowUsage "Missing work dir"
fi

if [ ! -d ${DestDir}/. ]; then
  Bail "'$DestDir' is missing or not a directory"
fi

if [ ! -d ${WorkDirRoot}/. ]; then
  Bail "'$WorkDirRoot' is missing or not a directory"
fi

set -e

if [ -z "$SourceDir" ]; then
  SourceDir=$(cd $(dirname $0)/.. && pwd)
else
  SourceDir=$(cd $SourceDir && pwd)
fi

DestDir=$(cd $DestDir && pwd)

WorkDirRoot=$(cd $WorkDirRoot && pwd)

SubWorkDir=selinux
WorkDir=${WorkDirRoot}/$SubWorkDir

mkdir -p $WorkDir

cp $SourceDir/installer/selinux/auoms.{te,fc} $WorkDir
pushd $WorkDir
make -f /usr/share/selinux/devel/Makefile
popd

mkdir -p $DestDir/selinux
cp $WorkDir/auoms.pp $DestDir/selinux
