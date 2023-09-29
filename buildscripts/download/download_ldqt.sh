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

LINUXDEPLOYQT_VERSION=6fcaf74384b309f517d5471981774b43707c9fc6
LINUXDEPLOYQT_HASH=71dabb4d15afd8c9420464d3fd741103a90e45c9199b24c15eecee91a28751b1

source "$(dirname "$(realpath "$0")")/common.sh"

download_verify_extract_tarball \
    "https://github.com/probonopd/linuxdeployqt/archive/${LINUXDEPLOYQT_VERSION}.tar.gz" \
    "${LINUXDEPLOYQT_HASH}"
