FROM ubuntu:18.04
MAINTAINER Tad Glines taglines@microsoft.com

RUN useradd -m -s /bin/bash build

ADD build_deps.list /home/build/build_deps.list
ADD download-build-deps.sh /home/build/download-build-deps.sh
ADD cross.aarch64 /home/build/cross-aarch64/.config
ADD cross.x86_64 /home/build/cross-x86_64/.config
ADD user-config.jam /root/user-config.jam

RUN apt-get update -y \
 && apt-get upgrade -y \
 && apt-get install -y wget gcc g++ flex texinfo xz-utils unzip help2man file patch gawk make libtool-bin libncurses5-dev autoconf python cmake \
 && cd /root \
 && wget http://crosstool-ng.org/download/crosstool-ng/crosstool-ng-1.24.0.tar.bz2 \
 && echo "d200d1ea5e2056c60d2b11b3f2721d30e53e817e1e0050fffaca074864e2f523  crosstool-ng-1.24.0.tar.bz2" | sha256sum -c - \
 && tar jxf crosstool-ng-1.24.0.tar.bz2 \
 && cd crosstool-ng-1.24.0 \
 && ./configure --prefix=/opt/ctng \
 && make \
 && make install \
 && rm -rf /root/crosstool-ng-* \
 && chown -R build /home/build \
 && mkdir /opt/x-tools \
 && chown build /opt/x-tools \
 && chmod +x /home/build/download-build-deps.sh \
 && su -c '/home/build/download-build-deps.sh' build \
 && su -c 'export PATH=$PATH:/opt/ctng/bin && cd /home/build/cross-x86_64 && ct-ng build' build \
 && su -c 'export PATH=$PATH:/opt/ctng/bin && cd /home/build/cross-aarch64 && ct-ng build' build \
 && chown -R root.root /opt/x-tools \
 && cd /root \
 && tar jxf /home/build/build-deps/boost_1_65_1.tar.bz2 \
 && cd boost_1_65_1 \
 && mkdir -p /opt/boost_1_65_1/include \
 && mkdir -p /opt/boost_1_65_1_x86_64/lib \
 && mkdir -p /opt/boost_1_65_1_aarch64/lib \
 && ./bootstrap.sh --prefix=/opt/boost_1_65_1_x86_64 \
 && ./b2 toolset=gcc-x86_64 link=static --with-test \
 && cp stage/lib/*.a /opt/boost_1_65_1_x86_64/lib \
 && ./bootstrap.sh --prefix=/opt/boost_1_65_1_aarch64 \
 && ./b2 toolset=gcc-aarch64 link=static --with-test \
 && cp stage/lib/*.a /opt/boost_1_65_1_aarch64/lib \
 && mv boost /opt/boost_1_65_1/include \
 && ln -s /opt/boost_1_65_1/include /opt/boost_1_65_1_x86_64/include \
 && ln -s /opt/boost_1_65_1/include /opt/boost_1_65_1_aarch64/include \
 && rm -rf boost_1_65_1 \
 && ln -s /opt/boost_1_65_1_x86_64 /opt/x-tools/x86_64-msft-linux-gnu/boost \
 && ln -s /opt/boost_1_65_1_aarch64 /opt/x-tools/aarch64-msft-linux-gnu/boost \
 && apt-get remove -y gcc g++ \
 && apt-get autoremove -y \
 && rm -rf /home/build/build-deps \
 && rm -rf /home/build/cross-x86_64 \
 && rm -rf /home/build/cross-aarch64
