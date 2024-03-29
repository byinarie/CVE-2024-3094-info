#!/usr/bin/env bash
# Likely only works on Linux due to GNU Find, probably needs to be ported for BSD utils

OPTIONAL_FIND_ARGS=-xdev  # Remove if you don't have slow remote mounts etc.

# Start with liblzma
LIBS=liblzma.so.5

LIB_DIRS="/usr/lib /lib"
BIN_DIRS="/usr/bin /bin /usr/local/bin"

RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

test_lib() {
    local lib_path
    lib_path="$1"

    deps=$(ldd "$lib_path" 2>/dev/null)
    for lib in $LIBS; do
        if [[ "$deps" == *"${lib}"* ]]; then
            echo -e "${YELLOW}${lib_path}${NC} depends on potentially problematic ${YELLOW}${lib}${NC}"
            LIBS="$LIBS $lib_path"
            return
        fi
    done
}

find_affected_libs() {
    for lib_dir in $LIB_DIRS; do
        find "${lib_dir}" $OPTIONAL_FIND_ARGS -type f -name "*.so*" | while read -r file; do test_lib "$file"; done;
    done
}

test_binary() {
    local bin_path
    bin_path="$1"

    deps=$(ldd "$bin_path" 2>/dev/null)
    for lib in $LIBS; do
        if [[ "$deps" == *"${lib}"* ]]; then
            echo -e "${RED}${bin_path}${NC} depends on potentially problematic ${YELLOW}${lib}${NC}"
            return
        fi
    done
}

find_affected_binaries() {
    for bin_dir in $BIN_DIRS; do
        find "${bin_dir}" $OPTIONAL_FIND_ARGS -type f -executable | while read -r file; do test_binary "$file"; done;
    done
}

#find_affected_libs
find_affected_binaries
