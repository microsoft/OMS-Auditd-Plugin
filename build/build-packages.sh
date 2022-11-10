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
Arch=x86_64

ShowUsage()
{
  cat << EOF
  Error: $1

  Usage: $0 -d <dest dir> -w <work dir> [ -a <architecture> ] [ -s <source dir> ] [ -b <bin dir> ] [ -p  <se pol dir> ] [ -bt <build type > ] [ -bn <build number > ]

    -d  <dest dir>     - Where built packages will be placed
    -w  <work dir>     - Directory where work dir will be placed
    -a  <architecture> - Target architecture (x86_64, aarch64) . Default: x86_64
    -s  <source dir>   - Root of source code
    -b  <bin dir>      - Location of bin dir (<bin dir>/bin) if binaries are not located in <dest dir>/bin
    -p  <se pol dir>   - Location of selinux policy dir if policy files are not located in <dest dir>/selinux
    -bt <build type>   - The build type (Debug, Release, RelWithDebInfo). Default: RelWithDebInfo
    -bn <build number> - The build number

EOF
    exit 1
}

Bail()
{
  echo "Error: $1"
  exit 1
}

SKIP_CLEAN=0

while (( "$#" )); do
  if [ "$1" == "-d" ]; then
    shift
    DestDir=$1
  elif [ "$1" == "-w" ]; then
    shift
    WorkDirRoot=$1
  elif [ "$1" == "-a" ]; then
    shift
    Arch=$1
  elif [ "$1" == "-s" ]; then
    shift
    SourceDir=$1
  elif [ "$1" == "-b" ]; then
    shift
    BinDir=$1
  elif [ "$1" == "-p" ]; then
    shift
    SEPolDir=$1
  elif [ "$1" == "-bt" ]; then
    shift
    BuildType=$1
  elif [ "$1" == "-bn" ]; then
    shift
    BuildNumber=$1
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

if [ "$Arch" != "x86_64" -a "$Arch" != "aarch64" ]; then
  Bail "Invalid architecture: $Arch"
fi

set -e

if [ -z "$SourceDir" ]; then
  SourceDir=$(cd $(dirname $0)/.. && pwd)
else
  SourceDir=$(cd $SourceDir && pwd)
fi

DestDir=$(cd $DestDir && pwd)

WorkDirRoot=$(cd $WorkDirRoot && pwd)

if [ -n "$BinDir" ]; then
  mkdir -p $DestDir/bin
  cp $BinDir/bin/auoms* $DestDir/bin
fi

if [ -n "$SEPolDir" ]; then
  mkdir -p $DestDir/selinux
  cp $SEPolDir/auoms* $DestDir/selinux
fi

SubWorkDir=$BuildType-$Arch
WorkDir=${WorkDirRoot}/$SubWorkDir
PseudoDir=${WorkDir}/pseudo-state
StageDir=${WorkDir}/stage
IntermediateDir=${WorkDir}/intermediate

mkdir -p $StageDir
mkdir -p $IntermediateDir

. $SourceDir/auoms.version

BUILD_NUMBER=${BuildNumber:-$AUOMS_BUILDVERSION_BUILDNR}

#cp $BinDir/bin/* $TargetDir/bin

pushd $DestDir

PSEUDO_OPTS=""
if [ $(id -u) -ne 0 ]; then
  mkdir -p $PseudoDir
fi

PseudoPython()
{
    if [ $(id -u) -ne 0 ]; then
        PSEUDO_PREFIX=/usr PSEUDO_LOCALSTATEDIR=$PseudoDir pseudo python $*
    else
        python $*
    fi
}

PseudoPython $SourceDir/installer/InstallBuilder/installbuilder.py \
		--BASE_DIR=$SourceDir \
		--TARGET_DIR=$DestDir \
		--INTERMEDIATE_DIR=$IntermediateDir \
		--STAGING_DIR=$StageDir \
		--BUILD_TYPE=DPKG \
		--PFARCH=$Arch \
		--VERSION=${AUOMS_BUILDVERSION_MAJOR}.${AUOMS_BUILDVERSION_MINOR}.${AUOMS_BUILDVERSION_PATCH} \
		--RELEASE=${BUILD_NUMBER} \
		--DATAFILE_PATH=$SourceDir/installer/datafiles \
		base_auoms.data linux.data linux_dpkg.data

if [ $(id -u) -ne 0 ]; then
  rm -rf $PseudoDir/*
fi
rm -rf $StageDir/*

PseudoPython $SourceDir/installer/InstallBuilder/installbuilder.py \
		--BASE_DIR=$SourceDir \
		--TARGET_DIR=$DestDir \
		--INTERMEDIATE_DIR=$IntermediateDir \
		--STAGING_DIR=$StageDir \
		--BUILD_TYPE=RPM \
		--PFARCH=$Arch \
		--VERSION=${AUOMS_BUILDVERSION_MAJOR}.${AUOMS_BUILDVERSION_MINOR}.${AUOMS_BUILDVERSION_PATCH} \
		--RELEASE=${BUILD_NUMBER} \
		--DATAFILE_PATH=$SourceDir/installer/datafiles \
		base_auoms.data linux.data linux_rpm.data

if [ $(id -u) -ne 0 ]; then
  rm -rf $PseudoDir/*
fi
rm -rf $StageDir/*

if [ "$BuildType" == "RelWithDebInfo" ]; then
  PseudoPython $SourceDir/installer/InstallBuilder/installbuilder.py \
      --BASE_DIR=$SourceDir \
      --TARGET_DIR=$DestDir \
      --INTERMEDIATE_DIR=$IntermediateDir \
      --STAGING_DIR=$StageDir \
      --BUILD_TYPE=DPKG \
      --PFARCH=$Arch \
      --VERSION=${AUOMS_BUILDVERSION_MAJOR}.${AUOMS_BUILDVERSION_MINOR}.${AUOMS_BUILDVERSION_PATCH} \
      --RELEASE=${BUILD_NUMBER} \
      --DATAFILE_PATH=$SourceDir/installer/datafiles-debug \
      base_auoms.data linux.data linux_dpkg.data

  if [ $(id -u) -ne 0 ]; then
    rm -rf $PseudoDir/*
  fi
  rm -rf $StageDir/*

  PseudoPython $SourceDir/installer/InstallBuilder/installbuilder.py \
      --BASE_DIR=$SourceDir \
      --TARGET_DIR=$DestDir \
      --INTERMEDIATE_DIR=$IntermediateDir \
      --STAGING_DIR=$StageDir \
      --BUILD_TYPE=RPM \
      --PFARCH=$Arch \
      --VERSION=${AUOMS_BUILDVERSION_MAJOR}.${AUOMS_BUILDVERSION_MINOR}.${AUOMS_BUILDVERSION_PATCH} \
      --RELEASE=${BUILD_NUMBER} \
      --DATAFILE_PATH=$SourceDir/installer/datafiles-debug \
      base_auoms.data linux.data linux_rpm.data

  if [ $(id -u) -ne 0 ]; then
    rm -rf $PseudoDir/*
  fi
  rm -rf $StageDir/*
fi