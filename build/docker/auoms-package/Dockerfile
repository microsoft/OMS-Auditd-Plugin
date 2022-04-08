FROM centos:6
MAINTAINER Tad Glines taglines@microsoft.com

# Edit the repos files to use vault.centos.org instead (a snapshot of older centos trees/repos)
## Reference: https://msazure.visualstudio.com/Security%20Health%20and%20Analysis/_git/VSA-LinuxAgent/pullrequest/4021747?_a=files
RUN sed -i 's/^mirrorlist/#mirrorlist/' /etc/yum.repos.d/*.repo && \
    sed -i 's/^#\s*baseurl=http:\/\/mirror\.centos\.org\/centos\//baseurl=http:\/\/vault\.centos\.org\//' /etc/yum.repos.d/*.repo && \
    sed -i 's/\$releasever/6.10/g' /etc/yum.repos.d/*.repo

# Install initial dev env
RUN yum update -y \
 && yum install -y epel-release \
 && yum install -y \
    wget \
    tar \
    bzip2 \
    zip \
    unzip \
    which \
    python \
    rpm-devel \
    rpm-build \
    dpkg-dev \
    selinux-policy-devel \
 && yum clean all

RUN yum install -y gcc sqlite-devel \
 && cd /root \
 && wget -q --no-check-certificate https://git.yoctoproject.org/pseudo/snapshot/pseudo-1.9.0.tar.bz2 \
 && echo "baa9c0bdca864a23087b8a33e97ad57f3acd084f9cbce131bcd356fb47f98f34  pseudo-1.9.0.tar.bz2" | sha256sum -c - \
 && tar jxf pseudo-1.9.0.tar.bz2 \
 && cd pseudo-1.9.0 \
 && ./configure --prefix=/opt/pseudo \
 && make \
 && make install \
 && yum remove -y gcc cpp cloog-ppl ppl sqlite-devel \
 && yum clean all
