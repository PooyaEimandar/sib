#!/usr/bin/env bash

source ./const.sh

CURRENT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
BUILD_TYPE="${1:-debug}"

if [[ "$PLATFORM" != "Linux" ]]; then
    echo "Seastar only supports Linux. Detected: $PLATFORM"
    exit 1
fi

if [ -z "$JOBS" ]; then
  if command -v nproc >/dev/null 2>&1; then
    JOBS=$(nproc)
  else
    JOBS=$(sysctl -n hw.logicalcpu)
  fi
fi

if [ "$JOBS" -gt 4 ]; then 
  JOBS=4
elif [ "$JOBS" -lt 1 ]; then
  JOBS=1
fi

if [ ! -d "seastar" ]; then
  INFO "Cloning seastar repository..."
  git clone --depth 1 https://github.com/scylladb/seastar.git #--recursive
else
  INFO "Updating seastar repository..."
  cd seastar || exit 1
  git pull --rebase
  git submodule update --init #--recursive
  cd ..
fi

cd seastar || exit 1
sudo ./install-dependencies.sh || exit 1
./configure.py --mode=$BUILD_TYPE --prefix="_cooking/installed"
ninja -C build/$BUILD_TYPE -j "$JOBS" || exit 1
ninja -C build/$BUILD_TYPE install
