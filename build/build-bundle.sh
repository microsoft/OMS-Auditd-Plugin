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

Arch=x86_64

ShowUsage()
{
  cat << EOF
  Error: $1

  Usage: $0 -d <dest dir> -w <work dir> -p <package dir> [ -a <architecture> ] [ -n <bundle name> ]

    -d  <dest dir>     - Where built bundle will be placed
    -w  <work dir>     - Directory where work dir will be placed
    -a  <architecture> - Target architecture (x86_64, aarch64) . Default: x86_64
    -p  <package dir>  - Dir with packages
    -n <bundle name>   - Desired bundle file name

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
  elif [ "$1" == "-p" ]; then
    shift
    PackageDir=$1
  elif [ "$1" == "-a" ]; then
    shift
    Arch=$1
  elif [ "$1" == "-n" ]; then
    shift
    BundleName=$1
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

SourceDir=$(cd $(dirname $0)/.. && pwd)

DestDir=$(cd $DestDir && pwd)

WorkDirRoot=$(cd $WorkDirRoot && pwd)

SubWorkDir=$Arch
WorkDir=${WorkDirRoot}/$SubWorkDir

mkdir -p $WorkDir
if [ $? -ne 0 ]; then
    Bail "Failed to create '$WorkDir' dir"
fi

case $Arch in
  x86_64)
    RPM_ARCH=x86_64
    DPKG_ARCH=amd64
    UARCH=x64
    ;;
  aarch64)
    RPM_ARCH=aarch64
    DPKG_ARCH=arm64
    UARCH=arm64
    ;;
  *)
    echo "Invalid arch: $Arch"
    exit 1
    ;;
esac

RPM_PKG=$(ls ${PackageDir}/auoms-[0-9]*.${RPM_ARCH}.rpm)

if [ -z "$RPM_PKG" ] || [ ! -e $RPM_PKG ]; then
    Bail "Failed to find RPM package"
fi

DPKG_PKG=$(ls ${PackageDir}/auoms-[0-9]*.${DPKG_ARCH}.deb)

if [ -z "$DPKG_PKG" ] || [ ! -e $DPKG_PKG ]; then
    Bail "Failed to find DPKG package"
fi

RPM_VERSION=$(basename $RPM_PKG | sed 's/auoms-\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*-[^.][^.]*\).*/\1/')
DPKG_VERSION=$(basename $DPKG_PKG | sed 's/auoms-\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*-[^.][^.]*\).*/\1/')

if [ "$RPM_VERSION" != "$DPKG_VERSION" ]; then
  Bail "RPM version ($RPM_VERSION) does not match DPKG version ($DPKG_VERSION)"
fi

VERSION=$RPM_VERSION

PACKAGE_PREFIX=auoms-${VERSION}.universal.$UARCH

cp $RPM_PKG $WorkDir/${PACKAGE_PREFIX}.rpm
if [ $? -ne 0 ]; then
    Bail "Failed to copy rpm file"
fi

cp $DPKG_PKG $WorkDir/${PACKAGE_PREFIX}.deb
if [ $? -ne 0 ]; then
    Bail "Failed to copy deb file"
fi

tar cvf $WorkDir/${PACKAGE_PREFIX}.tar -C $WorkDir ${PACKAGE_PREFIX}.{deb,rpm}
if [ $? -ne 0 ]; then
    Bail "Failed to create tar file"
fi

$SourceDir/installer/bundle/create_bundle.sh ${DestDir} $WorkDir ${PACKAGE_PREFIX}.tar
if [ $? -ne 0 ]; then
    Bail "Failed to create bundle"
fi

if [ ! -e ${DestDir}/${PACKAGE_PREFIX}.sh ]; then
    Bail "Failed to create bundle"
fi
