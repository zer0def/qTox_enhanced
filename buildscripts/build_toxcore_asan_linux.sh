#!/bin/bash

#    Copyright © 2021 by The qTox Project Contributors
#
#    This program is libre software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

set -euo pipefail

readonly SCRIPT_DIR="$(dirname "$(realpath "$0")")"

build_toxcore() {
    mkdir -p toxcore
    pushd toxcore >/dev/null || exit 1

    "${SCRIPT_DIR}/download/download_toxcore.sh"

    patch -Np1 < "${SCRIPT_DIR}/patches/tc___ftv2_capabilities.patch"

    if [ "${1-}""x" != "x" ]; then
        echo "using custom flags: -D${1-}"
        cmake . \
            -DCMAKE_C_FLAGS=" -D${1-} -fno-omit-frame-pointer -fsanitize=address -static-libasan -fstack-protector-all --param=ssp-buffer-size=1" \
            -DCMAKE_CXX_FLAGS=" -D${1-} -fno-omit-frame-pointer -fsanitize=address -static-libasan -fstack-protector-all --param=ssp-buffer-size=1" \
            -DBOOTSTRAP_DAEMON=OFF \
            -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON \
            -DCMAKE_BUILD_TYPE=Release \
            .
    else
        cmake . \
            -DCMAKE_C_FLAGS="-fno-omit-frame-pointer -fsanitize=address -static-libasan -fstack-protector-all --param=ssp-buffer-size=1" \
            -DCMAKE_CXX_FLAGS="-fno-omit-frame-pointer -fsanitize=address -static-libasan -fstack-protector-all --param=ssp-buffer-size=1" \
            -DBOOTSTRAP_DAEMON=OFF \
            -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON \
            -DCMAKE_BUILD_TYPE=Release \
            .
    fi

    cmake --build . -- -j$(nproc)
    cmake --build . --target install

    popd >/dev/null
}

build_toxext() {
    mkdir -p toxext
    pushd toxext >/dev/null || exit 1

    "${SCRIPT_DIR}/download/download_toxext.sh"

    cmake . -DCMAKE_BUILD_TYPE=Release
    cmake --build . -- -j$(nproc)
    cmake --build . --target install

    popd >/dev/null
}

build_toxext_messages() {
    mkdir -p toxext_messages
    pushd toxext_messages > /dev/null || exit 1

    "${SCRIPT_DIR}/download/download_toxext_messages.sh"

    cmake .  -DCMAKE_BUILD_TYPE=Release
    cmake --build . -- -j$(nproc)
    cmake --build . --target install

    popd >/dev/null
}

build_toxcore "${1-}"
build_toxext
build_toxext_messages
