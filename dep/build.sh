#!/usr/bin/env bash

# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
# This source code modified based on Facebook's Proxygen which is licensed under the BSD-style license

source ./const.sh

BUILD_FOR_FUZZING=false
FUZZING_ENGINE='-fsanitize=fuzzer'
NO_JEMALLOC=false

PROXYGEN_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

CMAKE_BUILD_TYPE="${1:-Release}"
FOLLY_VERSION="$2"
if [[ "$3" == "ON" ]]; then
  BUILD_PROXYGEN=true
else
  BUILD_PROXYGEN=false
fi

install_dependencies_linux() {
  sudo apt install -yq \
    git \
    cmake \
    m4 \
    gcc \
    g++ \
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
    ccache
}

install_dependencies_mac() {
  # install the default dependencies from homebrew
  brew install               \
    cmake                    \
    jemalloc                 \
    boost                    \
    bzip2                    \
    m4                       \
    double-conversion        \
    gflags                   \
    gperf                    \
    libevent                 \
    lz4                      \
    snappy                   \
    xz                       \
    openssl                  \
    libsodium                \
    ccache

  brew link                 \
    cmake                   \
    jemalloc                \
    boost                   \
    bzip2                   \
    double-conversion       \
    gflags                  \
    gperf                   \
    libevent                \
    lz4                     \
    snappy                  \
    openssl                 \
    xz                      \
    libsodium               \
    ccache
}

install_dependencies() {
  ECHO_INFO "install dependencies for $PLATFORM"
  if [ "$PLATFORM" = "Linux" ]; then
    install_dependencies_linux
  elif [ "$PLATFORM" = "Mac" ]; then
    install_dependencies_mac
  else
    ECHO_ERR "unsupported platform: $PLATFORM"
    exit 1
  fi
}

synch_dependency_to_commit() {
  # Utility function to synch a dependency to a specific commit. Takes two arguments:
  #   - $1: folder of the dependency's git repository
  #   - $2: path to the text file containing the desired commit hash
  DEP_REV=$(sed 's/Subproject commit //' "$2")
  pushd "$1"
  git fetch
  # Disable git warning about detached head when checking out a specific commit.
  git -c advice.detachedHead=false checkout "$DEP_REV"
  popd
}

setup_fast_float() {
  FAST_FLOAT_DIR=$DEPS_DIR/fast_float
  FAST_FLOAT_BUILD_DIR=$DEPS_DIR/fast_float/build/

  if [ ! -d "$FAST_FLOAT_DIR" ] ; then
    ECHO_INFO "Cloning fast_float repo"
    git clone https://github.com/fastfloat/fast_float.git "$FAST_FLOAT_DIR" --depth 1
  fi

  cd "$FAST_FLOAT_DIR"
  git fetch --tags
  git checkout "v8.0.0"
  
  ECHO_INFO "Building fast_float"
  mkdir -p "$FAST_FLOAT_BUILD_DIR"
  cd "$FAST_FLOAT_BUILD_DIR" || exit

  PARALLEL_LEVEL=$JOBS cmake -G Ninja          \
    -DCMAKE_PREFIX_PATH="$DEPS_DIR"            \
    -DCMAKE_INSTALL_PREFIX="$DEPS_DIR"         \
    -DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE       \
    -DCMAKE_C_COMPILER_LAUNCHER=ccache         \
    -DCMAKE_CXX_COMPILER_LAUNCHER=ccache       \
    ..
  
  ninja -C .
  ninja install
  ECHO_INFO "fast_float is installed"
  cd "$BWD" || exit
}

setup_glog() {
  GLOG_DIR=$DEPS_DIR/glog
  GLOG_BUILD_DIR=$DEPS_DIR/glog/build/
  GLOG_TAG=$(grep "subdir = " ../../build/fbcode_builder/manifests/glog | cut -d "-" -f 2)

  if [ ! -d "$GLOG_DIR" ] ; then
    ECHO_INFO "Cloning glog repo"
    git clone https://github.com/google/glog.git "$GLOG_DIR" --depth 1
  fi

  cd "$GLOG_DIR"
  git fetch --tags
  git checkout "v${GLOG_TAG}"
  
  ECHO_INFO "Building glog"
  mkdir -p "$GLOG_BUILD_DIR"
  cd "$GLOG_BUILD_DIR" || exit

  PARALLEL_LEVEL=$JOBS cmake -G Ninja          \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5         \
    -DCMAKE_PREFIX_PATH="$DEPS_DIR"            \
    -DCMAKE_INSTALL_PREFIX="$DEPS_DIR"         \
    -DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE       \
    -DCMAKE_C_COMPILER_LAUNCHER=ccache         \
    -DCMAKE_CXX_COMPILER_LAUNCHER=ccache       \
    ..
  
  ninja -C .
  ninja install
  ECHO_INFO "glog is installed"
  cd "$BWD" || exit
}

setup_fmt() {
  FMT_DIR=$DEPS_DIR/fmt
  FMT_BUILD_DIR=$DEPS_DIR/fmt/build/
  FMT_TAG=$(grep "subdir = " ../../build/fbcode_builder/manifests/fmt | cut -d "-" -f 2)
  if [ ! -d "$FMT_DIR" ] ; then
    ECHO_INFO "Cloning fmt repo"
    git clone https://github.com/fmtlib/fmt.git  "$FMT_DIR" --depth 1
  fi
  cd "$FMT_DIR"
  git fetch --tags
  git checkout "${FMT_TAG}"
  ECHO_INFO "Building fmt"
  mkdir -p "$FMT_BUILD_DIR"
  cd "$FMT_BUILD_DIR" || exit

  PARALLEL_LEVEL=$JOBS cmake -G Ninja          \
    -DCMAKE_PREFIX_PATH="$DEPS_DIR"            \
    -DCMAKE_INSTALL_PREFIX="$DEPS_DIR"         \
    -DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE       \
    -DCMAKE_C_COMPILER_LAUNCHER=ccache         \
    -DCMAKE_CXX_COMPILER_LAUNCHER=ccache       \
    -DFMT_DOC=OFF                              \
    -DFMT_TEST=OFF                             \
    ..
  ninja -C .
  ninja install
  ECHO_INFO "fmt is installed"
  cd "$BWD" || exit
}

setup_googletest() {
  GTEST_DIR=$DEPS_DIR/googletest
  GTEST_BUILD_DIR=$DEPS_DIR/googletest/build/
  GTEST_TAG=$(grep "subdir = " ../../build/fbcode_builder/manifests/googletest | cut -d "-" -f 2,3)
  if [ ! -d "$GTEST_DIR" ] ; then
    ECHO_INFO "Cloning googletest repo"
    git clone https://github.com/google/googletest.git  "$GTEST_DIR" --depth 1
  fi
  cd "$GTEST_DIR"
  git fetch --tags
  git checkout "${GTEST_TAG}"
  ECHO_INFO "Building googletest"
  mkdir -p "$GTEST_BUILD_DIR"
  cd "$GTEST_BUILD_DIR" || exit

  PARALLEL_LEVEL=$JOBS cmake -G Ninja          \
    -DCMAKE_PREFIX_PATH="$DEPS_DIR"            \
    -DCMAKE_INSTALL_PREFIX="$DEPS_DIR"         \
    -DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE       \
    -DCMAKE_C_COMPILER_LAUNCHER=ccache         \
    -DCMAKE_CXX_COMPILER_LAUNCHER=ccache       \
    ..
  ninja -C .
  ninja install
  ECHO_INFO "googletest is installed"
  cd "$BWD" || exit
}

setup_zstd() {
  ZSTD_DIR=$DEPS_DIR/zstd
  ZSTD_BUILD_DIR=$DEPS_DIR/zstd/build/cmake/builddir
  ZSTD_INSTALL_DIR=$DEPS_DIR
  ZSTD_TAG=$(grep "subdir = " ../../build/fbcode_builder/manifests/zstd | cut -d "-" -f 2 | cut -d "/" -f 1)
  if [ ! -d "$ZSTD_DIR" ] ; then
    ECHO_INFO "Cloning zstd repo"
    git clone https://github.com/facebook/zstd.git "$ZSTD_DIR" --depth 1
  fi
  cd "$ZSTD_DIR"
  git fetch --tags
  git checkout "v${ZSTD_TAG}"
  ECHO_INFO "Building Zstd"
  mkdir -p "$ZSTD_BUILD_DIR"
  cd "$ZSTD_BUILD_DIR" || exit

  PARALLEL_LEVEL=$JOBS cmake -G Ninja               \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5              \
    -DCMAKE_C_COMPILER_LAUNCHER=ccache              \
    -DCMAKE_CXX_COMPILER_LAUNCHER=ccache            \
    -DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE            \
    -DCMAKE_PREFIX_PATH="$ZSTD_INSTALL_DIR"         \
    -DCMAKE_INSTALL_PREFIX="$ZSTD_INSTALL_DIR"      \
    ${CMAKE_EXTRA_ARGS[@]+"${CMAKE_EXTRA_ARGS[@]}"} \
    ..
  ninja -C .
  ninja install
  ECHO_INFO "Zstd is installed"
  cd "$BWD" || exit
}

setup_folly() {

  FOLLY_DIR=$DEPS_DIR/folly
  FOLLY_BUILD_DIR=$DEPS_DIR/folly/build/

  if [ ! -d "$FOLLY_DIR" ] ; then
    ECHO_INFO "Cloning folly repo"
    git clone https://github.com/facebook/folly.git "$FOLLY_DIR" 
  fi
  synch_dependency_to_commit "$FOLLY_DIR" "$PROXYGEN_DIR"/proxygen/build/deps/github_hashes/facebook/folly-rev.txt
  if [ "$PLATFORM" = "Mac" ]; then
    # Homebrew installs OpenSSL in a non-default location on MacOS >= Mojave
    # 10.14 because MacOS has its own SSL implementation.  If we find the
    # typical Homebrew OpenSSL dir, load OPENSSL_ROOT_DIR so that cmake
    # will find the Homebrew version.
    dir=/usr/local/opt/openssl
    dir_new=/opt/homebrew/opt/openssl
    if [ -d $dir ]; then
        ECHO_INFO "using $dir openssl"
        export OPENSSL_ROOT_DIR=$dir
    elif [ -d $dir_new ]; then
        ECHO_INFO "using $dir_new openssl"
        export OPENSSL_ROOT_DIR=$dir_new
    fi
  fi
  ECHO_INFO "Building Folly"
  mkdir -p "$FOLLY_BUILD_DIR"
  cd "$FOLLY_BUILD_DIR" || exit
  MAYBE_DISABLE_JEMALLOC=""
  if [ "$NO_JEMALLOC" == true ] ; then
    MAYBE_DISABLE_JEMALLOC="-DFOLLY_USE_JEMALLOC=0"
  fi

  MAYBE_USE_STATIC_DEPS=""
  MAYBE_USE_STATIC_BOOST=""
  MAYBE_BUILD_SHARED_LIBS=""
  if [ "$BUILD_FOR_FUZZING" == true ] ; then
    MAYBE_USE_STATIC_DEPS="-DUSE_STATIC_DEPS_ON_UNIX=ON"
    MAYBE_USE_STATIC_BOOST="-DBOOST_LINK_STATIC=ON"
    MAYBE_BUILD_SHARED_LIBS="-DBUILD_SHARED_LIBS=OFF"
  fi

  # ignore fmt of the system
  PARALLEL_LEVEL=$JOBS cmake -G Ninja          \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5         \
    -DCMAKE_PREFIX_PATH="$DEPS_DIR"            \
    -DCMAKE_INSTALL_PREFIX="$DEPS_DIR"         \
    -DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE       \
    -DCMAKE_C_COMPILER_LAUNCHER=ccache         \
    -DCMAKE_CXX_COMPILER_LAUNCHER=ccache       \
    -DBUILD_TESTS=OFF                          \
    -DCMAKE_CXX_STANDARD=20                    \
    "$MAYBE_USE_STATIC_DEPS"                   \
    "$MAYBE_USE_STATIC_BOOST"                  \
    "$MAYBE_BUILD_SHARED_LIBS"                 \
    $MAYBE_DISABLE_JEMALLOC                    \
    ..
  ninja -C .
  ninja install

  ECHO_INFO "Folly is installed"
  cd "$BWD" || exit
}

setup_fizz() {
  FIZZ_DIR=$DEPS_DIR/fizz
  FIZZ_BUILD_DIR=$DEPS_DIR/fizz/build/
  if [ ! -d "$FIZZ_DIR" ] ; then
    ECHO_INFO "Cloning fizz repo"
    git clone https://github.com/facebookincubator/fizz "$FIZZ_DIR"
  fi
  synch_dependency_to_commit "$FIZZ_DIR" "$PROXYGEN_DIR"/proxygen/build/deps/github_hashes/facebookincubator/fizz-rev.txt
  ECHO_INFO "Building Fizz"
  mkdir -p "$FIZZ_BUILD_DIR"
  cd "$FIZZ_BUILD_DIR" || exit

  MAYBE_USE_STATIC_DEPS=""
  MAYBE_USE_SODIUM_STATIC_LIBS=""
  MAYBE_BUILD_SHARED_LIBS=""
  if [ "$BUILD_FOR_FUZZING" == true ] ; then
    MAYBE_USE_STATIC_DEPS="-DUSE_STATIC_DEPS_ON_UNIX=ON"
    MAYBE_USE_SODIUM_STATIC_LIBS="-Dsodium_USE_STATIC_LIBS=ON"
    MAYBE_BUILD_SHARED_LIBS="-DBUILD_SHARED_LIBS=OFF"
  fi

  PARALLEL_LEVEL=$JOBS cmake -G Ninja          \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5         \
    -DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE       \
    -DCMAKE_PREFIX_PATH="$DEPS_DIR"            \
    -DCMAKE_INSTALL_PREFIX="$DEPS_DIR"         \
    -DCMAKE_C_COMPILER_LAUNCHER=ccache         \
    -DCMAKE_CXX_COMPILER_LAUNCHER=ccache       \
    -DBUILD_TESTS=OFF                          \
    -DBUILD_EXAMPLES=OFF                       \
    "$MAYBE_USE_STATIC_DEPS"                   \
    "$MAYBE_BUILD_SHARED_LIBS"                 \
    "$MAYBE_USE_SODIUM_STATIC_LIBS"            \
    "$FIZZ_DIR/fizz"
  ninja -C .
  ninja install
  ECHO_INFO "Fizz is installed"
  cd "$BWD" || exit
}

setup_wangle() {
  WANGLE_DIR=$DEPS_DIR/wangle
  WANGLE_BUILD_DIR=$DEPS_DIR/wangle/build/
  if [ ! -d "$WANGLE_DIR" ] ; then
    ECHO_INFO "Cloning wangle repo"
    git clone https://github.com/facebook/wangle "$WANGLE_DIR"
  fi
  synch_dependency_to_commit "$WANGLE_DIR" "$PROXYGEN_DIR"/proxygen/build/deps/github_hashes/facebook/wangle-rev.txt
  ECHO_INFO "Building Wangle"
  mkdir -p "$WANGLE_BUILD_DIR"
  cd "$WANGLE_BUILD_DIR" || exit

  MAYBE_USE_STATIC_DEPS=""
  MAYBE_BUILD_SHARED_LIBS=""
  if [ "$BUILD_FOR_FUZZING" == true ] ; then
    MAYBE_USE_STATIC_DEPS="-DUSE_STATIC_DEPS_ON_UNIX=ON"
    MAYBE_BUILD_SHARED_LIBS="-DBUILD_SHARED_LIBS=OFF"
  fi

  PARALLEL_LEVEL=$JOBS cmake -G Ninja          \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5         \
    -DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE       \
    -DCMAKE_PREFIX_PATH="$DEPS_DIR"            \
    -DCMAKE_INSTALL_PREFIX="$DEPS_DIR"         \
    -DCMAKE_C_COMPILER_LAUNCHER=ccache         \
    -DCMAKE_CXX_COMPILER_LAUNCHER=ccache       \
    -DBUILD_TESTS=OFF                          \
    "$MAYBE_USE_STATIC_DEPS"                   \
    "$MAYBE_BUILD_SHARED_LIBS"                 \
    "$WANGLE_DIR/wangle"
  ninja -C .
  ninja install
  ECHO_INFO "Wangle is installed"
  cd "$BWD" || exit
}

setup_mvfst() {
  MVFST_DIR=$DEPS_DIR/mvfst
  MVFST_BUILD_DIR=$DEPS_DIR/mvfst/build/
  if [ ! -d "$MVFST_DIR" ] ; then
    ECHO_INFO "Cloning mvfst repo"
    git clone https://github.com/facebook/mvfst "$MVFST_DIR"
  fi
  synch_dependency_to_commit "$MVFST_DIR" "$PROXYGEN_DIR"/proxygen/build/deps/github_hashes/facebook/mvfst-rev.txt
  ECHO_INFO "Building Mvfst"
  mkdir -p "$MVFST_BUILD_DIR"
  cd "$MVFST_BUILD_DIR" || exit

  MAYBE_USE_STATIC_DEPS=""
  MAYBE_BUILD_SHARED_LIBS=""
  if [ "$BUILD_FOR_FUZZING" == true ] ; then
    MAYBE_USE_STATIC_DEPS="-DUSE_STATIC_DEPS_ON_UNIX=ON"
    MAYBE_BUILD_SHARED_LIBS="-DBUILD_SHARED_LIBS=OFF"
  fi

  PARALLEL_LEVEL=$JOBS cmake -G Ninja          \
    -DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE       \
    -DCMAKE_PREFIX_PATH="$DEPS_DIR"            \
    -DCMAKE_INSTALL_PREFIX="$DEPS_DIR"         \
    -DCMAKE_C_COMPILER_LAUNCHER=ccache         \
    -DCMAKE_CXX_COMPILER_LAUNCHER=ccache       \
    -DBUILD_TESTS=OFF                          \
    "$MAYBE_USE_STATIC_DEPS"                   \
    "$MAYBE_BUILD_SHARED_LIBS"                 \
    "$MVFST_DIR"
  ninja -C .
  ninja install
  ECHO_INFO "Mvfst is installed"
  cd "$BWD" || exit
}

setup_libevent() {
  LIBEVENT_DIR=$DEPS_DIR/libevent
  LIBEVENT_BUILD_DIR=$DEPS_DIR/libevent/build/
  
  if [ ! -d "$LIBEVENT_DIR" ] ; then
    ECHO_INFO "Cloning libevent repo"
    git clone https://github.com/libevent/libevent.git "$LIBEVENT_DIR"
  fi

  cd "$LIBEVENT_DIR"
  git fetch --tags
  git checkout "master"

  ECHO_INFO "Building libevent"
  mkdir -p "$LIBEVENT_BUILD_DIR"
  cd "$LIBEVENT_BUILD_DIR" || exit

  PARALLEL_LEVEL=$JOBS cmake -G Ninja          \
    -DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE       \
    -DCMAKE_C_COMPILER_LAUNCHER=ccache         \
    -DCMAKE_CXX_COMPILER_LAUNCHER=ccache       \
    -DCMAKE_INSTALL_PREFIX="$DEPS_DIR"         \
    -DEVENT__DISABLE_TESTS=ON                  \
    -DEVENT__DISABLE_BENCHMARK=ON              \
    -DEVENT__DISABLE_SAMPLES=ON                \
    -DBUILD_SHARED_LIBS=ON                     \
    ..

  ninja -C .
  ninja install

  ECHO_INFO "libevent is installed"
  cd "$BWD" || exit
}


detect_platform
if [[ "$PLATFORM" == UNKNOWN* ]]; then
  ECHO_ERR "Unsupported platform: $PLATFORM"
  exit 1
fi

if [ -z "$JOBS" ]; then
  if command -v nproc >/dev/null 2>&1; then
    JOBS=$(nproc)
  else
    JOBS=$(sysctl -n hw.logicalcpu)
  fi
fi

install_dependencies

# check proxygen folder exists
if [ ! -d "proxygen" ]; then
    ECHO_INFO "cloning Proxygen"
    git clone https://github.com/facebook/proxygen.git --depth 1 --branch $FOLLY_VERSION
    cd proxygen/proxygen
else
    ECHO_INFO "updating Proxygen"
    cd proxygen
    git pull
    cd proxygen
fi

BUILD_DIR=_build
mkdir -p $BUILD_DIR

set -e nounset
trap 'cd $PROXYGEN_DIR' EXIT
cd $BUILD_DIR || exit
BWD=$(pwd)
ECHO_INFO "Building Proxygen in $BWD"
DEPS_DIR=$BWD/deps
mkdir -p "$DEPS_DIR"

# Must execute from the directory containing this script
cd "$(dirname "$0")"

# on mac temporary ignore fmt package of brew
if [ "$PLATFORM" = "Mac" ]; then
  if [ -d /opt/homebrew/include/fmt ]; then
    mv /opt/homebrew/include/fmt /opt/homebrew/include/fmt_backup
    # Ensure fmt package is reverted on exit or any error
    trap 'mv /opt/homebrew/include/fmt_backup /opt/homebrew/include/fmt' EXIT
  fi
fi

if $BUILD_PROXYGEN; then
  ECHO_INFO "Building dependencies of Proxygen"

  setup_fast_float
  setup_glog
  setup_fmt
  setup_googletest
  setup_zstd
  setup_libevent
  setup_folly
  setup_fizz
  setup_wangle
  setup_mvfst

  ECHO_INFO "Building Proxygen"

  MAYBE_BUILD_FUZZERS=""
  MAYBE_LIB_FUZZING_ENGINE=""
  MAYBE_USE_STATIC_DEPS=""
  MAYBE_BUILD_SHARED_LIBS=""
  if [ "$BUILD_FOR_FUZZING" == true ] ; then
    MAYBE_BUILD_FUZZERS="-DBUILD_FUZZERS=ON"
    MAYBE_LIB_FUZZING_ENGINE="-DLIB_FUZZING_ENGINE=$FUZZING_ENGINE"
    MAYBE_USE_STATIC_DEPS="-DUSE_STATIC_DEPS_ON_UNIX=ON"
    MAYBE_BUILD_SHARED_LIBS="-DBUILD_SHARED_LIBS=OFF"
  fi

  if [ -z "$PREFIX" ]; then
    PREFIX=$BWD
  fi

  # Build proxygen with cmake
  cd "$BWD" || exit
  ECHO_INFO "Building proxygen in $BWD in $CMAKE_BUILD_TYPE mode"
  PARALLEL_LEVEL=$JOBS cmake -G Ninja          \
    -DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE       \
    -DCMAKE_C_COMPILER_LAUNCHER=ccache         \
    -DCMAKE_CXX_COMPILER_LAUNCHER=ccache       \
    -DCMAKE_PREFIX_PATH="$DEPS_DIR"            \
    -DCMAKE_INSTALL_PREFIX="$PREFIX"           \
    -DCMAKE_CXX_STANDARD=20                    \
    -DBUILD_SAMPLES=ON                         \
    -DBUILD_TESTS=ON                           \
    "$MAYBE_BUILD_FUZZERS"                     \
    "$MAYBE_LIB_FUZZING_ENGINE"                \
    "$MAYBE_USE_STATIC_DEPS"                   \
    "$MAYBE_BUILD_SHARED_LIBS"                 \
    ../..

  ninja -C .
  ECHO_INFO "Proxygen built successfully"

else
  ECHO_INFO "Building dependencies of Folly"

  setup_fast_float
  setup_glog
  setup_fmt
  setup_googletest
  setup_libevent
  setup_folly

  ECHO_INFO "Folly built successfully"
fi