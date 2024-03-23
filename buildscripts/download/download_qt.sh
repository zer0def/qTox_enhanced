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

QT_MAJOR=5
QT_MINOR=15
QT_PATCH=13
QT_HASH=9550ec8fc758d3d8d9090e261329700ddcd712e2dda97e5fcfeabfac22bea2ca
source "$(dirname "$(realpath "$0")")/common.sh"

#    https://download.qt.io/archive/qt/${QT_MAJOR}.${QT_MINOR}/${QT_MAJOR}.${QT_MINOR}.${QT_PATCH}/single/qt-everywhere-opensource-src-${QT_MAJOR}.${QT_MINOR}.${QT_PATCH}.tar.xz \
#    https://download.qt.io/archive/qt/${QT_MAJOR}.${QT_MINOR}/${QT_MAJOR}.${QT_MINOR}.${QT_PATCH}/single/qt-everywhere-src-${QT_MAJOR}.${QT_MINOR}.${QT_PATCH}.tar.xz \

download_verify_extract_tarball \
    https://download.qt.io/archive/qt/${QT_MAJOR}.${QT_MINOR}/${QT_MAJOR}.${QT_MINOR}.${QT_PATCH}/single/qt-everywhere-opensource-src-${QT_MAJOR}.${QT_MINOR}.${QT_PATCH}.tar.xz \
    "${QT_HASH}"
