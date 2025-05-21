FROM ubuntu:24.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    git \
    cmake \
    m4 \
    gcc-13 \
    g++-13 \
    clang-format \
    clang-tidy \
    ninja-build \
    flex \
    bison \
    libunwind-dev \
    libgflags-dev \
    libkrb5-dev \
    libsasl2-dev \
    libnuma-dev \
    pkg-config \
    libssl-dev \
    libcap-dev \
    gperf \
    libevent-dev \
    libtool \
    libboost-all-dev \
    libjemalloc-dev \
    libsnappy-dev \
    wget \
    unzip \
    libiberty-dev \
    liblz4-dev \
    liblzma-dev \
    make \
    zlib1g-dev \
    binutils-dev \
    libsodium-dev \
    libdouble-conversion-dev \
    python3-venv  \
    libsecret-1-dev \
    ccache \
 && rm -rf /var/lib/apt/lists/*

# Set compiler environment
ENV CC=gcc-13
ENV CXX=g++-13
ENV AR=gcc-ar-13
ENV RANLIB=gcc-ranlib-13
ENV CMAKE_C_COMPILER_LAUNCHER=ccache
ENV CMAKE_CXX_COMPILER_LAUNCHER=ccache

# Clone SIB repository with submodules
WORKDIR /sib
RUN git clone --depth 1 https://github.com/PooyaEimandar/sib.git .

# Copy TechEmpower-style entry point
COPY ./main.cpp ./techempower/main.cpp

# Run Proxygen/Folly build via your CMake script
RUN cmake -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DSIB_TECHEMPOWER=ON \
    -DSIB_NET_PROXYGEN=ON \
 && cmake --build build -- -j$(nproc)

EXPOSE 8080

CMD ["./build/sib_techempower"]