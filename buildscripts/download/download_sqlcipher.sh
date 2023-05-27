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

SQLCIPHER_VERSION=4.5.4
SQLCIPHER_HASH=ea052fe634d729f9dd6b624016104de796faf87e487a9e868a07faee35957771

source "$(dirname "$(realpath "$0")")/common.sh"

download_verify_extract_tarball \
    "https://github.com/sqlcipher/sqlcipher/archive/v${SQLCIPHER_VERSION}.tar.gz" \
    "${SQLCIPHER_HASH}"
