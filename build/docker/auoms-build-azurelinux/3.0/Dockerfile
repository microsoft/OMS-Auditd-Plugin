FROM mcr.microsoft.com/onebranch/azurelinux/build:3.0

RUN mkdir -m 777 -p /sources && \
    ln -s /usr/src/linux /sources

ENV TZ=America/Los_Angeles
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN tdnf update -qy tdnf && \
        tdnf install -y azurelinux-repos-debug

RUN tdnf -y install \
                acl \
                bcc-devel \
                binutils-devel \
                bison \
                boost-devel \
                cdrkit \
                cereal-devel \
                clang-devel \
                curl \
                dnf \
                dnf-utils \
                dosfstools \
                dwarves \
                elfutils-libelf-devel \
                flex \
                gawk \
                gcc \
                gdb \
                g++ \
                git \
                glibc-devel \
                gmock-devel \
                gtest-devel \
                golang \
                kernel-headers \
                libbpf-devel \
                libcap-devel \
                libpcap-devel \
                lldb-devel \
                llvm-devel \
                make \
                msgpack-devel \
                parted \
                pigz \
                python3 \
                qemu-img \
                rapidjson-devel \
                re2-devel \
                re2-20240201 \
                rpm \
                rpm-build \
                rsync \
                sudo \
                tar \
                valgrind \
                vim-extra \
                wget
