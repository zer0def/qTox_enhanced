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

# use toxcore with enhanced ToxAV
TOXCORE_VERSION="096c6f016b4b5f27ad80f3ebb6d1fcf52f53e719" # 0.2.18 enhanced
TOXCORE_HASH="b253329b91cb2768883016a6022dde9d117390c17595576f9c8516411810c334"

source "$(dirname "$(realpath "$0")")/common.sh"

download_verify_extract_tarball \
    https://github.com/zoff99/c-toxcore/archive/"$TOXCORE_VERSION".tar.gz \
    "$TOXCORE_HASH"
