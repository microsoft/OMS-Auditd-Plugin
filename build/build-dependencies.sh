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

  Usage: $0 -s <archive dir> -d <dest include dir> -l <dest lib dir> [ -t <toolset> ]

    -s <archive dir>      - The dir where source archives reside
    -i <dest include dir> - Where to place include files
    -l <dest lib dir>     - Where to place compiled libs
    -t <toolset>          - Toolset to use
EOF
    exit 1
}

Bail()
{
  echo "Error: $1"
  exit 1
}

while (( "$#" )); do
  if [ "$1" == "-s" ]; then
    shift
    ArchiveDir=$1
  elif [ "$1" == "-i" ]; then
    shift
    IncludeDir=$1
  elif [ "$1" == "-l" ]; then
    shift
    LibDir=$1
  elif [ "$1" == "-t" ]; then
    shift
    Toolset=$1
  else
    ShowUsage "unsupported argument '$1'"
  fi
  shift
done

if [ -z "$ArchiveDir" ]; then
  ShowUsage "Missing archive dir"
fi

if [ -z "$IncludeDir" ]; then
  ShowUsage "Missing include dir"
fi

if [ -z "$LibDir" ]; then
  ShowUsage "Missing lib dir"
fi

if [ ! -d $ArchiveDir ]; then
  Bail "'$ArchiveDir' is missing or not a directory"
fi

if [ ! -d $IncludeDir ]; then
  Bail "'$IncludeDir' is missing or not a directory"
fi

if [ ! -d $LibDir ]; then
  Bail "'$LibDir' is missing or not a directory"
fi

set -e

if [ -e ${IncludeDir}/rapidjson ]; then
  rm -rf ${IncludeDir}/rapidjson
fi
tar zxf ${ArchiveDir}/rapidjson-1.0.2.tar.gz --strip-components=2 -C ${IncludeDir} rapidjson-1.0.2/include/rapidjson

if [ -e ${IncludeDir}/msgpack ]; then
  rm -rf ${IncludeDir}/msgpack.*
  rm -rf ${IncludeDir}/msgpack
fi
unzip -d ${IncludeDir} ${ArchiveDir}/msgpack-c-cpp-2.0.0.zip "msgpack-c-cpp-2.0.0/include/*"
mv ${IncludeDir}/msgpack-c-cpp-2.0.0/include/* ${IncludeDir}
rm -rf ${IncludeDir}/msgpack-c-cpp-2.0.0

if [ -e ${IncludeDir}/re2 ]; then
  rm -rf ${IncludeDir}/re2
fi

mkdir -p ${IncludeDir}/re2

tmpdir=$(mktemp -d)

unzip -q -d $tmpdir ${ArchiveDir}/re2-2020-11-01.zip
pushd $tmpdir/re2-2020-11-01
if [ -n "$Toolset" ]; then
  CC=${Toolset}-gcc CXX=${Toolset}-g++ make static
else
  make static
fi
popd
cp $tmpdir/re2-2020-11-01/re2/{filtered_re2.h,re2.h,set.h,stringpiece.h} ${IncludeDir}/re2
cp $tmpdir/re2-2020-11-01/obj/libre2.a $LibDir

rm -rf $tmpdir
