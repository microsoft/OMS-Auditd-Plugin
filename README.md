# OMS-Auditd-Plugin
Auditd plugin that forwards audit events to OMS Agent for Linux

# Build Instructions
## Env Setup
    git clone https://github.com/Microsoft/pal
    git clone https://github.com/microsoft/OMS-Auditd-Plugin
    cd OMS-Auditd-Plugin
    ROOT=$(pwd)

## Build Docker images
    cd build/docker
    docker build -t auoms-build auoms-build
    docker build -t auoms-build32 auoms-build32
    cd $ROOT

## Build 64bit auoms
    build/run-docker-build.sh

## Build 32bit auoms
    build/run-docker-build.sh 32
