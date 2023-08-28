#!/bin/bash


ShowUsage()
{
  cat << EOF
  Error: $1

  Usage: $0 -d <artifact dir> [ -a <architecture> ]

    -d <artifact dir>
    -a <artitecure>
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
    ArtifactDir=$1
  elif [ "$1" == "-a" ]; then
    shift
    Architecture=$1
  else
    ShowUsage "unsupported argument '$1'"
  fi
    shift
done

if [ -z "$ArtifactDir" ]; then
  ShowUsage "Missing artifact dir"
fi

if [ ! -d $ArtifactDir ]; then
  Bail "'$ArtifactDir' does not exist or is not a directory"
fi

if [ $(id -u) -ne 0 ]; then
    Bail "This script must be run as root"
fi

set -e
cd $ArtifactDir
echo "658ef347d12b9524518e4bb75bec4ef8634af84284e1cc7e714f777a61921c6d  aarch64-msft-linux-gnu.tar.bz2" | sha256sum -c -
echo "a33457695812ac302a2f604cab346a48a90d0b5987f984d29b8a36b0a45d368f  boost_1_65_1.tar.bz2" | sha256sum -c -
echo "131021bfb9e0a8a5f5d08173a3f4db44621f2ddbc15d3b84fd7b0f7885ab2d78  x86_64-msft-linux-gnu.tar.bz2" | sha256sum -c -

cd /

if [ -z "$Architecture" -o "$Architecture" == "x86_64" ]; then
    echo "Extracting $ArtifactDir/x86_64-msft-linux-gnu.tar.bz2"
    tar jxf $ArtifactDir/x86_64-msft-linux-gnu.tar.bz2
fi

if [ -z "$Architecture" -o "$Architecture" == "aarch64" ]; then
    echo "Extracting $ArtifactDir/aarch64-msft-linux-gnu.tar.bz2"
    tar jxf $ArtifactDir/aarch64-msft-linux-gnu.tar.bz2
fi

echo "Extracting $ArtifactDir/boost_1_65_1.tar.bz2"
tar jxf $ArtifactDir/boost_1_65_1.tar.bz2

if [ -z "$Architecture" -o "$Architecture" == "x86_64" ]; then
    echo "Linking boost into /opt/x-tools/x86_64-msft-linux-gnu"
    ln -s /opt/boost_1_65_1_x86_64 /opt/x-tools/x86_64-msft-linux-gnu/boost
fi

if [ -z "$Architecture" -o "$Architecture" == "aarch64" ]; then
    echo "Linking boost into /opt/x-tools/aarch64-msft-linux-gnu"
    ln -s /opt/boost_1_65_1_aarch64 /opt/x-tools/aarch64-msft-linux-gnu/boost
fi
