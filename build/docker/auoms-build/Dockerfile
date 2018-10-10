FROM centos:6
MAINTAINER Tad Glines taglines@microsoft.com

# Install initial dev env
RUN yum install -y centos-release-scl yum-utils \
 && yum-config-manager --enable rhel-server-rhscl-7-rpms \
 && yum install -y devtoolset-7-toolchain \
 && yum update -y && yum install -y epel-release \
 && yum install -y \
    sudo \
    lsof \
    net-tools \
    patch \
    git \
    wget \
    curl \
    tar \
    bzip2 \
    zip \
    unzip \
    which \
    cmake \
    rpm-devel \
    pam-devel \
    rpm-build \
    selinux-policy-devel \
    audit-libs-devel \
    boost148-devel \
 && yum clean all

RUN sed -i '/requiretty/d' /etc/sudoers \
    && echo "build ALL=(ALL) NOPASSWD:ALL" >>/etc/sudoers
