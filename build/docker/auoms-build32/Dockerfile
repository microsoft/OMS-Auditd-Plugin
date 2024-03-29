FROM i386/centos:6
MAINTAINER Tad Glines taglines@microsoft.com

# Install initial dev env
RUN sed -i 's/$basearch/i386/' /etc/yum.repos.d/*
ADD https://copr.fedorainfracloud.org/coprs/mlampe/devtoolset-7/repo/epel-6/mlampe-devtoolset-7-epel-6.repo /etc/yum.repos.d/mlampe-devtoolset-7-epel-6.repo
RUN yum install -y util-linux-ng.i686 \
 && linux32 yum install -y devtoolset-7-toolchain \
 && linux32 yum update -y && yum install -y epel-release \
 && linux32 yum install -y \
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

ENTRYPOINT ["/usr/bin/linux32"]