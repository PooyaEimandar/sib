#!/usr/bin/env bash

# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
# This source code modified based on Facebook's Proxygen which is licensed under the BSD-style license

source ./const.sh

BUILD_FOR_FUZZING=false
NO_BUILD_TESTS=true
NO_JEMALLOC=false

PROXYGEN_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

if [ -n "$1" ]; then
  CMAKE_BUILD_TYPE="$1"
else
  CMAKE_BUILD_TYPE="Release"
fi

FOLLY_VERSION=$2
if [[ "$3" == "ON" ]]; then
  BUILD_PROXYGEN=TRUE
else
  BUILD_PROXYGEN=FALSE
fi

install_dependencies_linux() {
  sudo apt install -yq \
    git \
    cmake \
    m4 \
    gcc-12 \
    g++-12 \
    g++ \
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
    libsecret-1-dev
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
    libsodium                

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
    libsodium               
}

install_dependencies() {
  echo -e "${COLOR_GREEN}[ INFO ] install dependencies ${COLOR_OFF}"
  if [ "$PLATFORM" = "Linux" ]; then
    install_dependencies_linux
  elif [ "$PLATFORM" = "Mac" ]; then
    install_dependencies_mac
  else
    echo -e "${COLOR_RED}[ ERROR ] unsupported platform: $PLATFORM ${COLOR_OFF}"
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
    echo -e "${COLOR_GREEN}[ INFO ] Cloning fast_float repo ${COLOR_OFF}"
    git clone https://github.com/fastfloat/fast_float.git "$FAST_FLOAT_DIR" --depth 1
  fi

  cd "$FAST_FLOAT_DIR"
  git fetch --tags
  git checkout "v8.0.0"
  
  echo -e "${COLOR_GREEN}Building fast_float ${COLOR_OFF}"
  mkdir -p "$FAST_FLOAT_BUILD_DIR"
  cd "$FAST_FLOAT_BUILD_DIR" || exit

  PARALLEL_LEVEL=$JOBS cmake -G Ninja             \
    -DCMAKE_PREFIX_PATH="$DEPS_DIR"               \
    -DCMAKE_INSTALL_PREFIX="$DEPS_DIR"            \
    -DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE          \
    "$MAYBE_OVERRIDE_CXX_FLAGS"                   \
    ..
  
  ninja -C .
  ninja install
  echo -e "${COLOR_GREEN}fast_float is installed ${COLOR_OFF}"
  cd "$BWD" || exit
}

setup_glog() {
  GLOG_DIR=$DEPS_DIR/glog
  GLOG_BUILD_DIR=$DEPS_DIR/glog/build/
  GLOG_TAG=$(grep "subdir = " ../../build/fbcode_builder/manifests/glog | cut -d "-" -f 2)

  if [ ! -d "$GLOG_DIR" ] ; then
    echo -e "${COLOR_GREEN}[ INFO ] Cloning glog repo ${COLOR_OFF}"
    git clone https://github.com/google/glog.git "$GLOG_DIR" --depth 1
  fi

  cd "$GLOG_DIR"
  git fetch --tags
  git checkout "v${GLOG_TAG}"
  
  echo -e "${COLOR_GREEN}Building glog ${COLOR_OFF}"
  mkdir -p "$GLOG_BUILD_DIR"
  cd "$GLOG_BUILD_DIR" || exit

  PARALLEL_LEVEL=$JOBS cmake -G Ninja             \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5            \
    -DCMAKE_PREFIX_PATH="$DEPS_DIR"               \
    -DCMAKE_INSTALL_PREFIX="$DEPS_DIR"            \
    -DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE          \
    "$MAYBE_OVERRIDE_CXX_FLAGS"                   \
    ..
  
  ninja -C .
  ninja install
  echo -e "${COLOR_GREEN}glog is installed ${COLOR_OFF}"
  cd "$BWD" || exit
}

setup_fmt() {
  FMT_DIR=$DEPS_DIR/fmt
  FMT_BUILD_DIR=$DEPS_DIR/fmt/build/
  FMT_TAG=$(grep "subdir = " ../../build/fbcode_builder/manifests/fmt | cut -d "-" -f 2)
  if [ ! -d "$FMT_DIR" ] ; then
    echo -e "${COLOR_GREEN}[ INFO ] Cloning fmt repo ${COLOR_OFF}"
    git clone https://github.com/fmtlib/fmt.git  "$FMT_DIR" --depth 1
  fi
  cd "$FMT_DIR"
  git fetch --tags
  git checkout "${FMT_TAG}"
  echo -e "${COLOR_GREEN}Building fmt ${COLOR_OFF}"
  mkdir -p "$FMT_BUILD_DIR"
  cd "$FMT_BUILD_DIR" || exit

  PARALLEL_LEVEL=$JOBS cmake -G Ninja             \
    -DCMAKE_PREFIX_PATH="$DEPS_DIR"               \
    -DCMAKE_INSTALL_PREFIX="$DEPS_DIR"            \
    -DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE          \
    "$MAYBE_OVERRIDE_CXX_FLAGS"                   \
    -DFMT_DOC=OFF                                 \
    -DFMT_TEST=OFF                                \
    ..
  ninja -C .
  ninja install
  echo -e "${COLOR_GREEN}fmt is installed ${COLOR_OFF}"
  cd "$BWD" || exit
}

setup_googletest() {
  GTEST_DIR=$DEPS_DIR/googletest
  GTEST_BUILD_DIR=$DEPS_DIR/googletest/build/
  GTEST_TAG=$(grep "subdir = " ../../build/fbcode_builder/manifests/googletest | cut -d "-" -f 2,3)
  if [ ! -d "$GTEST_DIR" ] ; then
    echo -e "${COLOR_GREEN}[ INFO ] Cloning googletest repo ${COLOR_OFF}"
    git clone https://github.com/google/googletest.git  "$GTEST_DIR" --depth 1
  fi
  cd "$GTEST_DIR"
  git fetch --tags
  git checkout "${GTEST_TAG}"
  echo -e "${COLOR_GREEN}Building googletest ${COLOR_OFF}"
  mkdir -p "$GTEST_BUILD_DIR"
  cd "$GTEST_BUILD_DIR" || exit

  PARALLEL_LEVEL=$JOBS cmake -G Ninja             \
    -DCMAKE_PREFIX_PATH="$DEPS_DIR"               \
    -DCMAKE_INSTALL_PREFIX="$DEPS_DIR"            \
    -DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE          \
    ..
  ninja -C .
  ninja install
  echo -e "${COLOR_GREEN}googletest is installed ${COLOR_OFF}"
  cd "$BWD" || exit
}

setup_zstd() {
  ZSTD_DIR=$DEPS_DIR/zstd
  ZSTD_BUILD_DIR=$DEPS_DIR/zstd/build/cmake/builddir
  ZSTD_INSTALL_DIR=$DEPS_DIR
  ZSTD_TAG=$(grep "subdir = " ../../build/fbcode_builder/manifests/zstd | cut -d "-" -f 2 | cut -d "/" -f 1)
  if [ ! -d "$ZSTD_DIR" ] ; then
    echo -e "${COLOR_GREEN}[ INFO ] Cloning zstd repo ${COLOR_OFF}"
    git clone https://github.com/facebook/zstd.git "$ZSTD_DIR" --depth 1
  fi
  cd "$ZSTD_DIR"
  git fetch --tags
  git checkout "v${ZSTD_TAG}"
  echo -e "${COLOR_GREEN}Building Zstd ${COLOR_OFF}"
  mkdir -p "$ZSTD_BUILD_DIR"
  cd "$ZSTD_BUILD_DIR" || exit

  PARALLEL_LEVEL=$JOBS cmake -G Ninja               \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5              \
    -DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE            \
    -DCMAKE_PREFIX_PATH="$ZSTD_INSTALL_DIR"         \
    -DCMAKE_INSTALL_PREFIX="$ZSTD_INSTALL_DIR"      \
    ${CMAKE_EXTRA_ARGS[@]+"${CMAKE_EXTRA_ARGS[@]}"} \
    ..
  ninja -C .
  ninja install
  echo -e "${COLOR_GREEN}Zstd is installed ${COLOR_OFF}"
  cd "$BWD" || exit
}

setup_folly() {

  FOLLY_DIR=$DEPS_DIR/folly
  FOLLY_BUILD_DIR=$DEPS_DIR/folly/build/

  if [ ! -d "$FOLLY_DIR" ] ; then
    echo -e "${COLOR_GREEN}[ INFO ] Cloning folly repo ${COLOR_OFF}"
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
        echo -e "${COLOR_GREEN}[ INFO ] using $dir openssl ${COLOR_OFF}"
        export OPENSSL_ROOT_DIR=$dir
    elif [ -d $dir_new ]; then
        echo -e "${COLOR_GREEN}[ INFO ] using $dir_new openssl ${COLOR_OFF}"
        export OPENSSL_ROOT_DIR=$dir_new
    fi
  fi
  echo -e "${COLOR_GREEN}Building Folly ${COLOR_OFF}"
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
  PARALLEL_LEVEL=$JOBS cmake -G Ninja             \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5            \
    -DCMAKE_PREFIX_PATH="$DEPS_DIR"               \
    -DCMAKE_INSTALL_PREFIX="$DEPS_DIR"            \
    -DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE          \
    -DBUILD_TESTS=OFF                             \
    -DCMAKE_CXX_STANDARD=20                       \
    "$MAYBE_USE_STATIC_DEPS"                      \
    "$MAYBE_USE_STATIC_BOOST"                     \
    "$MAYBE_BUILD_SHARED_LIBS"                    \
    "$MAYBE_OVERRIDE_CXX_FLAGS"                   \
    $MAYBE_DISABLE_JEMALLOC                       \
    ..
  ninja -C .
  ninja install

  echo -e "${COLOR_GREEN}Folly is installed ${COLOR_OFF}"
  cd "$BWD" || exit
}

setup_fizz() {
  FIZZ_DIR=$DEPS_DIR/fizz
  FIZZ_BUILD_DIR=$DEPS_DIR/fizz/build/
  if [ ! -d "$FIZZ_DIR" ] ; then
    echo -e "${COLOR_GREEN}[ INFO ] Cloning fizz repo ${COLOR_OFF}"
    git clone https://github.com/facebookincubator/fizz "$FIZZ_DIR"
  fi
  synch_dependency_to_commit "$FIZZ_DIR" "$PROXYGEN_DIR"/proxygen/build/deps/github_hashes/facebookincubator/fizz-rev.txt
  echo -e "${COLOR_GREEN}Building Fizz ${COLOR_OFF}"
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

  PARALLEL_LEVEL=$JOBS cmake -G Ninja           \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5          \
    -DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE        \
    -DCMAKE_PREFIX_PATH="$DEPS_DIR"             \
    -DCMAKE_INSTALL_PREFIX="$DEPS_DIR"          \
    -DBUILD_TESTS=OFF                           \
    -DBUILD_EXAMPLES=OFF                        \
    "$MAYBE_USE_STATIC_DEPS"                    \
    "$MAYBE_BUILD_SHARED_LIBS"                  \
    "$MAYBE_OVERRIDE_CXX_FLAGS"                 \
    "$MAYBE_USE_SODIUM_STATIC_LIBS"             \
    "$FIZZ_DIR/fizz"
  ninja -C .
  ninja install
  echo -e "${COLOR_GREEN}Fizz is installed ${COLOR_OFF}"
  cd "$BWD" || exit
}

setup_wangle() {
  WANGLE_DIR=$DEPS_DIR/wangle
  WANGLE_BUILD_DIR=$DEPS_DIR/wangle/build/
  if [ ! -d "$WANGLE_DIR" ] ; then
    echo -e "${COLOR_GREEN}[ INFO ] Cloning wangle repo ${COLOR_OFF}"
    git clone https://github.com/facebook/wangle "$WANGLE_DIR"
  fi
  synch_dependency_to_commit "$WANGLE_DIR" "$PROXYGEN_DIR"/proxygen/build/deps/github_hashes/facebook/wangle-rev.txt
  echo -e "${COLOR_GREEN}Building Wangle ${COLOR_OFF}"
  mkdir -p "$WANGLE_BUILD_DIR"
  cd "$WANGLE_BUILD_DIR" || exit

  MAYBE_USE_STATIC_DEPS=""
  MAYBE_BUILD_SHARED_LIBS=""
  if [ "$BUILD_FOR_FUZZING" == true ] ; then
    MAYBE_USE_STATIC_DEPS="-DUSE_STATIC_DEPS_ON_UNIX=ON"
    MAYBE_BUILD_SHARED_LIBS="-DBUILD_SHARED_LIBS=OFF"
  fi

  PARALLEL_LEVEL=$JOBS cmake -G Ninja           \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5          \
    -DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE        \
    -DCMAKE_PREFIX_PATH="$DEPS_DIR"             \
    -DCMAKE_INSTALL_PREFIX="$DEPS_DIR"          \
    -DBUILD_TESTS=OFF                           \
    "$MAYBE_USE_STATIC_DEPS"                    \
    "$MAYBE_BUILD_SHARED_LIBS"                  \
    "$MAYBE_OVERRIDE_CXX_FLAGS"                 \
    "$WANGLE_DIR/wangle"
  ninja -C .
  ninja install
  echo -e "${COLOR_GREEN}Wangle is installed ${COLOR_OFF}"
  cd "$BWD" || exit
}

setup_mvfst() {
  MVFST_DIR=$DEPS_DIR/mvfst
  MVFST_BUILD_DIR=$DEPS_DIR/mvfst/build/
  if [ ! -d "$MVFST_DIR" ] ; then
    echo -e "${COLOR_GREEN}[ INFO ] Cloning mvfst repo ${COLOR_OFF}"
    git clone https://github.com/facebook/mvfst "$MVFST_DIR"
  fi
  synch_dependency_to_commit "$MVFST_DIR" "$PROXYGEN_DIR"/proxygen/build/deps/github_hashes/facebook/mvfst-rev.txt
  echo -e "${COLOR_GREEN}Building Mvfst ${COLOR_OFF}"
  mkdir -p "$MVFST_BUILD_DIR"
  cd "$MVFST_BUILD_DIR" || exit

  MAYBE_USE_STATIC_DEPS=""
  MAYBE_BUILD_SHARED_LIBS=""
  if [ "$BUILD_FOR_FUZZING" == true ] ; then
    MAYBE_USE_STATIC_DEPS="-DUSE_STATIC_DEPS_ON_UNIX=ON"
    MAYBE_BUILD_SHARED_LIBS="-DBUILD_SHARED_LIBS=OFF"
  fi

  PARALLEL_LEVEL=$JOBS cmake -G Ninja           \
    -DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE        \
    -DCMAKE_PREFIX_PATH="$DEPS_DIR"             \
    -DCMAKE_INSTALL_PREFIX="$DEPS_DIR"          \
    -DBUILD_TESTS=OFF                           \
    "$MAYBE_USE_STATIC_DEPS"                    \
    "$MAYBE_BUILD_SHARED_LIBS"                  \
    "$MAYBE_OVERRIDE_CXX_FLAGS"                 \
    "$MVFST_DIR"
  ninja -C .
  ninja install
  echo -e "${COLOR_GREEN}Mvfst is installed ${COLOR_OFF}"
  cd "$BWD" || exit
}

setup_libevent() {
  LIBEVENT_DIR=$DEPS_DIR/libevent
  LIBEVENT_BUILD_DIR=$DEPS_DIR/libevent/build/
  
  if [ ! -d "$LIBEVENT_DIR" ] ; then
    echo -e "${COLOR_GREEN}[ INFO ] Cloning libevent repo ${COLOR_OFF}"
    git clone https://github.com/libevent/libevent.git "$LIBEVENT_DIR"
  fi

  cd "$LIBEVENT_DIR"
  git fetch --tags
  git checkout "master"

  echo -e "${COLOR_GREEN}Building libevent ${COLOR_OFF}"
  mkdir -p "$LIBEVENT_BUILD_DIR"
  cd "$LIBEVENT_BUILD_DIR" || exit

  PARALLEL_LEVEL=$JOBS cmake -G Ninja \
    -DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE \
    -DCMAKE_INSTALL_PREFIX="$DEPS_DIR" \
    -DEVENT__DISABLE_TESTS=ON \
    -DEVENT__DISABLE_BENCHMARK=ON \
    -DEVENT__DISABLE_SAMPLES=ON \
    -DBUILD_SHARED_LIBS=ON \
    ..

  ninja -C .
  ninja install

  echo -e "${COLOR_GREEN}libevent is installed ${COLOR_OFF}"
  cd "$BWD" || exit
}


detect_platform
if [[ "$PLATFORM" == UNKNOWN* ]]; then
  echo -e "${COLOR_RED}[ ERROR ] Unsupported platform: $PLATFORM ${COLOR_OFF}"
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
    echo "${COLOR_GREEN}[ INFO ] clone proxygen ${COLOR_OFF}"
    git clone https://github.com/facebook/proxygen.git --depth 1 --branch $FOLLY_VERSION
    cd proxygen/proxygen
else
    echo "${COLOR_GREEN}[ INFO ] update proxygen ${COLOR_OFF}"
    cd proxygen
    git pull
    cd proxygen
fi

MAYBE_OVERRIDE_CXX_FLAGS=""
if [ -n "$COMPILER_FLAGS" ] ; then
  MAYBE_OVERRIDE_CXX_FLAGS="-DCMAKE_CXX_FLAGS=$COMPILER_FLAGS"
fi

BUILD_DIR=_build
mkdir -p $BUILD_DIR

set -e nounset
trap 'cd $PROXYGEN_DIR' EXIT
cd $BUILD_DIR || exit
BWD=$(pwd)
echo -e "${COLOR_GREEN}Building in $BWD ${COLOR_OFF}"
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
  echo -e "${COLOR_GREEN}Building dependencies of Proxygen.${COLOR_OFF}"

  setup_fast_float
  setup_glog
  setup_fmt
  setup_googletest
  setup_zstd
  setup_folly
  setup_fizz
  setup_wangle
  setup_mvfst

  echo -e "${COLOR_GREEN}Building Proxygen.${COLOR_OFF}"

  MAYBE_BUILD_FUZZERS=""
  MAYBE_USE_STATIC_DEPS=""
  MAYBE_LIB_FUZZING_ENGINE=""
  MAYBE_BUILD_SHARED_LIBS=""
  MAYBE_BUILD_TESTS="-DBUILD_TESTS=ON"
  if [ "$NO_BUILD_TESTS" == true ] ; then
    MAYBE_BUILD_TESTS="-DBUILD_TESTS=OFF"
  fi
  if [ "$BUILD_FOR_FUZZING" == true ] ; then
    MAYBE_BUILD_FUZZERS="-DBUILD_FUZZERS=ON"
    MAYBE_USE_STATIC_DEPS="-DUSE_STATIC_DEPS_ON_UNIX=ON"
    MAYBE_LIB_FUZZING_ENGINE="-DLIB_FUZZING_ENGINE='$LIB_FUZZING_ENGINE'"
    MAYBE_BUILD_SHARED_LIBS="-DBUILD_SHARED_LIBS=OFF"
  fi

  if [ -z "$PREFIX" ]; then
    PREFIX=$BWD
  fi

  # Build proxygen with cmake
  cd "$BWD" || exit
  echo -e "${COLOR_GREEN}Building proxygen in $BWD in $CMAKE_BUILD_TYPE mode ${COLOR_OFF}"
  PARALLEL_LEVEL=$JOBS cmake -G Ninja       \
    -DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE    \
    -DCMAKE_PREFIX_PATH="$DEPS_DIR"         \
    -DCMAKE_INSTALL_PREFIX="$PREFIX"        \
    -DCMAKE_CXX_STANDARD=20                 \
    -DBUILD_SAMPLES=ON                      \
    "$MAYBE_BUILD_TESTS"                    \
    "$MAYBE_BUILD_FUZZERS"                  \
    "$MAYBE_BUILD_SHARED_LIBS"              \
    "$MAYBE_OVERRIDE_CXX_FLAGS"             \
    "$MAYBE_USE_STATIC_DEPS"                \
    "$MAYBE_LIB_FUZZING_ENGINE"             \
    ../..

  ninja -C .
  echo -e "${COLOR_GREEN}Proxygen built successfully.${COLOR_OFF}"

else
  echo -e "${COLOR_GREEN}Building dependencies of Folly.${COLOR_OFF}"

  setup_fast_float
  setup_glog
  setup_fmt
  setup_googletest
  setup_libevent
  setup_folly

  echo -e "${COLOR_GREEN}Folly built successfully.${COLOR_OFF}"
fi