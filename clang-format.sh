#!/usr/bin/env bash

# This script formats all C++ files in ./sib, ./test, and ./bench using clang-format in parallel.
# It excludes files in the "build" directory and any ".pb.cc" or ".pb.h" files.

# Check if clang-format is installed
if ! command -v clang-format &> /dev/null; then
    echo "clang-format could not be found. Please install it to use this script."
    exit 1
fi

# Find and format C++ files under ./sib, ./test, and ./bench (excluding build/ and protobuf files)
find ./sib ./test ./bench -type f \( -name "*.cpp" -o -name "*.hpp" -o -name "*.h" \) \
  ! -path "*/build/*" ! -name "*.pb.cc" ! -name "*.pb.h" \
  -print0 | xargs -0 -n1 -P"$(nproc)" clang-format -i

echo "All C++ files in sib, test, and bench have been formatted using $(nproc) cores."
