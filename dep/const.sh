#!/usr/bin/env bash

ARCH=$(uname -m)
PLATFORM="UNKNOWN"

# ANSI Color Codes
readonly COLOR_RED="\033[0;31m"
readonly COLOR_GREEN="\033[0;32m"
readonly COLOR_OFF="\033[0m"

INFO() {
    echo -e "${COLOR_GREEN}[INFO] $*${COLOR_OFF}"
}

ERR() {
    echo -e "${COLOR_RED}[ERROR] $*${COLOR_OFF}" >&2
}

# Check if a command exists
is_command_exists() {
    command -v "$1" &>/dev/null
}

# Detect host platform
detect_platform() {
    local unameOut
    unameOut="$(uname -s)"
    case "${unameOut}" in
        Linux*)     PLATFORM="Linux";;
        Darwin*)    PLATFORM="Mac";;
        *)          PLATFORM="UNKNOWN:${unameOut}";;
    esac
}
detect_platform
INFO "Detected platform: ${PLATFORM}"
INFO "Detected architecture: ${ARCH}"
