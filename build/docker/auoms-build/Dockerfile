FROM centos:6
MAINTAINER Tad Glines taglines@microsoft.com

# Edit the repos files to use vault.centos.org instead (a snapshot of older centos trees/repos)
## Reference: https://msazure.visualstudio.com/Security%20Health%20and%20Analysis/_git/VSA-LinuxAgent/pullrequest/4021747?_a=files
RUN sed -i 's/^mirrorlist/#mirrorlist/' /etc/yum.repos.d/*.repo && \
    sed -i 's/^#\s*baseurl=http:\/\/mirror\.centos\.org\/centos\//baseurl=http:\/\/vault\.centos\.org\//' /etc/yum.repos.d/*.repo && \
    sed -i 's/\$releasever/6.10/g' /etc/yum.repos.d/*.repo

# Install initial dev env
RUN yum update -y \
 && yum install -y centos-release-scl yum-utils \
 && yum-config-manager --enable rhel-server-rhscl-7-rpms \
 && sed -i 's/^#\s*baseurl=http:\/\/mirror\.centos\.org\/centos\//baseurl=http:\/\/vault\.centos\.org\//' /etc/yum.repos.d/*.repo \
 && sed -i 's/vault\.centos\.org\/6\//vault\.centos\.org\/6.10\//g' /etc/yum.repos.d/*.repo \
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
