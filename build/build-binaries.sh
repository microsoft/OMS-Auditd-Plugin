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

BuildType=RelWithDebInfo

ShowUsage()
{
  cat << EOF
  Error: $1

  Usage: $0 -d <dest dir> -w <work dir> [ -a <architecture> ] [ -s <source dir> ] [ -p <deps dir> ] [ -bt <build type> ] [ -m ] [ -x ]

    -d  <dest dir>     - Where built binares will be placed
    -w  <work dir>     - Directory where work dir will be placed
    -a  <architecture> - Target architecture
    -s  <source dir>   - Root of source code
    -p  <deps dir>     - Location of dependencies
    -bt <build type>   - The build type (Debug, Release, RelWithDebInfo). Default: RelWithDebInfo
    -m                 - Only do the cmake setup then exit
    -x                 - Don't remove work dir when done
EOF
    exit 1
}

Bail()
{
  echo "Error: $1"
  exit 1
}

JUST_CMAKE=0
SKIP_CLEAN=0

while (( "$#" )); do
  if [ "$1" == "-d" ]; then
    shift
    DestDir=$1
  elif [ "$1" == "-w" ]; then
    shift
    WorkDir=$1
  elif [ "$1" == "-a" ]; then
    shift
    Arch=$1
  elif [ "$1" == "-s" ]; then
    shift
    SourceDir=$1
  elif [ "$1" == "-p" ]; then
    shift
    DepsDir=$1
  elif [ "$1" == "-bt" ]; then
    shift
    BuildType=$1
  elif [ "$1" == "-m" ]; then
    JUST_CMAKE=1
  elif [ "$1" == "-x" ]; then
    SKIP_CLEAN=1
  else
    ShowUsage "unsupported argument '$1'"
  fi
  shift
done

if [ -z "$DestDir" ]; then
  ShowUsage "Missing destination dir"
fi

if [ -z "$WorkDir" ]; then
  ShowUsage "Missing work dir"
fi

if [ ! -d ${DestDir}/. ]; then
  Bail "'$DestDir' is missing or not a directory"
fi

if [ ! -d ${WorkDir}/. ]; then
  Bail "'$WorkDir' is missing or not a directory"
fi

if [ "$BuildType" != "Debug" -a "$BuildType" != "Release" -a "$BuildType" != "RelWithDebInfo" ]; then
  Bail "Invalid build type: $BuildType"
fi

DEPS_OPTION=""
if [ -n "$DepsDir" ]; then
  pushd $DepsDir
  DepsDir=$(pwd)
  popd
  if [ ! -e ${DepsDir}/include ]; then
    Bail "'${DepsDir}/include' is missing"
  fi
  if [ ! -e ${DepsDir}/lib ]; then
    Bail "'${DepsDir}/lib' is missing"
  fi
  DEPS_OPTION="-DDEPS_INCLUDE=${DepsDir}/include -DDEPS_LIB=${DepsDir}/lib"
fi

if [ -z "$SourceDir" ]; then
  pushd $(dirname $0)/..
  SourceDir=$(pwd)
  popd
else
  pushd $SourceDir
  SourceDir=$(pwd)
  popd
fi

ToolchainFile=""
if [ -n "$Arch" ]; then
  ToolchainFile="${SourceDir}/build/${Arch}.cmake"
  if [ ! -e ${ToolchainFile} ]; then
    Bail "Expected '${ToolchainFile}' does not exist"
  fi
fi

SubWorkDir=$BuildType
Toolchain=""
if [ -n "$Arch" ]; then
  SubWorkDir=${BuildType}-$Arch
  Toolchain="-DCMAKE_TOOLCHAIN_FILE=${ToolchainFile}"
fi

BuildDir=${WorkDir}/$SubWorkDir

if [ ! -e $BuildDir ]; then
  mkdir $BuildDir
  if [ $? -ne 0 ]; then
    Bail "Failed to create '$BuildDir'"
  fi
fi

pushd $BuildDir

cmake ${Toolchain} $DEPS_OPTION -DDO_STATIC_LINK=1 -DCMAKE_BUILD_TYPE=$BuildType ${SourceDir}
if [ $? -ne 0 ]; then
  Bail "cmake failed"
fi

if [ $JUST_CMAKE -eq 1 ]; then
  echo "Build dir '$BuildDir' is ready for use"
  exit 0
fi

make
if [ $? -ne 0 ]; then
  Bail "make failed"
fi

make install
if [ $? -ne 0 ]; then
  Bail "'make install' failed"
fi
popd

mkdir $DestDir/bin
if [ $? -ne 0 ]; then
  Bail "Failed to create '$DestDir/bin'"
fi

cp $BuildDir/release/bin/* $DestDir/bin
if [ $? -ne 0 ]; then
  Bail "Failed to copy binaries to dest dir"
fi

mkdir $DestDir/tests
if [ $? -ne 0 ]; then
  Bail "Failed to create '$DestDir/tests'"
fi

cp $BuildDir/*Tests $DestDir/tests
if [ $? -ne 0 ]; then
  Bail "Failed to copy binaries to dest dir"
fi

if [ $SKIP_CLEAN -eq 0 ]; then
  rm -rf $BuildDir
fi
