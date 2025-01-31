#! /bin/bash

id -a
pwd

export DEBIAN_FRONTEND=noninteractive

_HOME_=/home/runner/work/qTox_enhanced/qTox_enhanced

export ARCH=x86_64
export WINEARCH=win64
export SCRIPT_ARCH=${WINEARCH}


mkdir -p /build/download/
mkdir -p /build/patches/
mkdir -p /src/

ln -s /home/runner/work/qTox_enhanced/qTox_enhanced /qtox
ls -al /qtox/

dpkg --add-architecture i386 && \
    apt-get update && apt-get install -y --no-install-recommends \
                   autoconf \
                   automake \
                   build-essential \
                   ca-certificates \
                   cmake \
                   extra-cmake-modules \
                   git \
                   libarchive-tools \
                   libtool \
                   nsis \
                   pkg-config \
                   python3-pefile \
                   tclsh \
                   texinfo \
                   unzip \
                   curl \
                   gnupg \
                   yasm \
                   zip \
                   g++-mingw-w64-${ARCH//_/-} \
                   gcc-mingw-w64-${ARCH//_/-} \
                   gdb-mingw-w64
curl -L --connect-timeout 10 https://dl.winehq.org/wine-builds/winehq.key | apt-key add -
echo "deb https://dl.winehq.org/wine-builds/debian/ bullseye main" >> /etc/apt/sources.list.d/wine.list
apt-get update && apt-get install -y --no-install-recommends wine-stable
apt-get clean && \
    rm -rf /var/lib/apt/lists/*

update-alternatives --set ${ARCH}-w64-mingw32-gcc /usr/bin/${ARCH}-w64-mingw32-gcc-posix && \
  update-alternatives --set ${ARCH}-w64-mingw32-g++ /usr/bin/${ARCH}-w64-mingw32-g++-posix

cd "$_HOME_"/buildscripts/
cp -v download/common.sh /build/download/common.sh
cp -v build_utils.sh /build/build_utils.sh

cd "$_HOME_"/buildscripts/
cp -v download/download_nasm.sh /build/download/download_nasm.sh
cp -v build_nasm.sh /build/build_nasm.sh

mkdir -p /src/nasm && \
  cd /src/nasm && \
  /build/build_nasm.sh --arch ${SCRIPT_ARCH} && \
  rm -fr /src/nasm

cd "$_HOME_"/buildscripts/
cp -v download/download_libx264.sh /build/download/download_libx264.sh
cp -v build_libx264_windows.sh /build/build_libx264_windows.sh

mkdir -p /src/libx264 && \
  cd /src/libx264 && \
  /build/build_libx264_windows.sh --arch ${SCRIPT_ARCH} && \
  rm -fr /src/libx264

cd "$_HOME_"/buildscripts/
cp -v download/download_openssl.sh /build/download/download_openssl.sh
cp -v build_openssl.sh /build/build_openssl.sh

mkdir -p /src/openssl && \
  cd /src/openssl && \
  /build/build_openssl.sh --arch ${SCRIPT_ARCH} && \
  rm -fr /src/openssl

cd "$_HOME_"/buildscripts/
cp -v download/download_libcurl.sh /build/download/download_libcurl.sh
cp -v build_libcurl_windows.sh /build/build_libcurl_windows.sh

mkdir -p /src/curl && \
  cd /src/curl && \
  /build/build_libcurl_windows.sh --arch ${SCRIPT_ARCH} && \
  rm -fr /src/curl

cd "$_HOME_"/buildscripts/
cp -v download/download_qt.sh /build/download/download_qt.sh
cp -v build_qt_windows_download_only.sh /build/build_qt_windows_download_only.sh

df -h
mkdir -p /src/qt && \
  cd /src/qt && \
  /build/build_qt_windows_download_only.sh --arch ${SCRIPT_ARCH}
df -h

cd "$_HOME_"/buildscripts/
cp -v build_qt_windows.sh /build/build_qt_windows.sh

mkdir -p /src/qt && \
  cd /src/qt && \
  /build/build_qt_windows.sh --arch ${SCRIPT_ARCH} && \
  rm -fr /src/qt
df -h

cd "$_HOME_"/buildscripts/
cp -v download/download_sqlcipher.sh /build/download/download_sqlcipher.sh
cp -v build_sqlcipher.sh /build/build_sqlcipher.sh

mkdir -p /src/sqlcipher && \
  cd /src/sqlcipher && \
  /build/build_sqlcipher.sh  --arch ${SCRIPT_ARCH} && \
  rm -fr /src/sqlcipher

cd "$_HOME_"/buildscripts/
cp -v download/download_ffmpeg.sh /build/download/download_ffmpeg.sh
cp -v build_ffmpeg.sh /build/build_ffmpeg.sh
mkdir -p /src/ffmpeg && \
  cd /src/ffmpeg && \
  /build/build_ffmpeg.sh --arch ${SCRIPT_ARCH} && \
  rm -fr /src/ffmpeg

cd "$_HOME_"/buildscripts/
cp -v toolchain/windows-${ARCH}-toolchain.cmake /build/windows-toolchain.cmake

cd "$_HOME_"/buildscripts/
cp -v download/download_openal.sh /build/download/download_openal.sh
cp -v build_openal.sh /build/build_openal.sh
cp -v patches/openal-cmake-3-11.patch /build/patches/openal-cmake-3-11.patch

mkdir -p /src/openal && \
  cd /src/openal && \
  /build/build_openal.sh --arch ${SCRIPT_ARCH} && \
  rm -fr /src/openal

cd "$_HOME_"/buildscripts/
cp -v download/download_qrencode.sh /build/download/download_qrencode.sh
cp -v build_qrencode.sh /build/build_qrencode.sh
mkdir -p /src/qrencode && \
  cd /src/qrencode && \
  /build/build_qrencode.sh  --arch ${SCRIPT_ARCH} && \
  rm -fr /src/qrencode

cd "$_HOME_"/buildscripts/
cp -v download/download_libexif.sh /build/download/download_libexif.sh
cp -v build_libexif.sh /build/build_libexif.sh
mkdir -p /src/exif && \
  cd /src/exif && \
  /build/build_libexif.sh --arch ${SCRIPT_ARCH} && \
  rm -fr /src/exif

cd "$_HOME_"/buildscripts/
cp -v download/download_snore.sh /build/download/download_snore.sh
cp -v build_snore_windows.sh /build/build_snore_windows.sh
mkdir -p /src/snore && \
  cd /src/snore && \
  /build/build_snore_windows.sh && \
  rm -fr /src/snore

cd "$_HOME_"/buildscripts/
cp -v download/download_opus.sh /build/download/download_opus.sh
cp -v build_opus.sh /build/build_opus.sh
mkdir -p /src/opus && \
  cd /src/opus && \
  /build/build_opus.sh --arch ${SCRIPT_ARCH} && \
  rm -fr /src/opus

cd "$_HOME_"/buildscripts/
cp -v download/download_sodium.sh /build/download/download_sodium.sh
cp -v build_sodium.sh /build/build_sodium.sh
mkdir -p /src/sodium && \
  cd /src/sodium && \
  /build/build_sodium.sh --arch ${SCRIPT_ARCH} && \
  rm -fr /src/sodium

cd "$_HOME_"/buildscripts/
cp -v download/download_vpx.sh /build/download/download_vpx.sh
cp -v build_vpx.sh /build/build_vpx.sh
cp -v patches/vpx-windows.patch /build/patches/vpx-windows.patch
mkdir -p /src/vpx && \
  cd /src/vpx && \
  /build/build_vpx.sh --arch ${SCRIPT_ARCH} && \
  rm -fr /src/vpx

cd "$_HOME_"/buildscripts/
cp -v download/download_mingw_ldd.sh /build/download/download_mingw_ldd.sh
cp -v build_mingw_ldd_windows.sh /build/build_mingw_ldd_windows.sh
mkdir -p /src/mingw_ldd && \
  cd /src/mingw_ldd && \
  /build/build_mingw_ldd_windows.sh && \
  rm -fr /src/mingw_ldd

cd "$_HOME_"/buildscripts/
cp -v download/download_nsisshellexecasuser.sh /build/download/download_nsisshellexecasuser.sh
cp -v build_nsisshellexecasuser_windows.sh /build/build_nsisshellexecasuser_windows.sh
mkdir -p /src/nsisshellexecasuser && \
  cd /src/nsisshellexecasuser && \
  /build/build_nsisshellexecasuser_windows.sh && \
  rm -fr /src/nsisshellexecasuser

cd "$_HOME_"/buildscripts/
cp -v download/download_toxcore.sh /build/download/download_toxcore.sh
cp -v download/download_toxext.sh /build/download/download_toxext.sh
cp -v download/download_toxext_messages.sh /build/download/download_toxext_messages.sh
cp -v build_toxcore.sh /build/build_toxcore.sh
cp -v patches/*.patch /build/patches/
mkdir -p /src/tox && \
  cd /src/tox && \
  /build/build_toxcore.sh && \
  rm -fr /src/tox

mkdir -p /export && \
  cp /usr/${ARCH}-w64-mingw32/lib/libwinpthread-1.dll /export/ && \
  cp /usr/lib/gcc/${ARCH}-w64-mingw32/10-posix/libgcc_s_*-1.dll /export && \
  cp /usr/lib/gcc/${ARCH}-w64-mingw32/10-posix/libstdc++-6.dll /export && \
  cp /usr/lib/gcc/${ARCH}-w64-mingw32/10-posix/libssp-0.dll /export && \
  cp /windows/bin/Qt5Core.dll /export && \
  cp /windows/bin/Qt5Gui.dll /export && \
  cp /windows/bin/Qt5Network.dll /export && \
  cp /windows/bin/Qt5Svg.dll /export && \
  cp /windows/bin/Qt5Xml.dll /export && \
  cp /windows/bin/Qt5Widgets.dll /export && \
  cp /windows/bin/avcodec-*.dll /export && \
  cp /windows/bin/avdevice-*.dll /export && \
  cp /windows/bin/avformat-*.dll /export && \
  cp /windows/bin/avutil-*.dll /export && \
  cp /windows/bin/libexif-*.dll /export && \
  cp /windows/lib/libqrencode.dll /export && \
  cp /windows/bin/libsodium-*.dll /export && \
  cp /windows/bin/libsqlcipher-*.dll /export && \
  cp /windows/bin/swscale-*.dll /export && \
  cp /windows/bin/libcrypto-*.dll /export && \
  cp /windows/bin/libtoxcore.dll /export && \
  cp /windows/bin/libopus-*.dll /export && \
  cp /windows/lib/libvpx.a /export && \
  cp /windows/bin/OpenAL32.dll /export && \
  cp /windows/bin/libssl-*.dll /export && \
  cp /windows/bin/libsnore-qt5.dll /export && \
  mkdir -p /export/libsnore-qt5/ && \
  cp /windows/plugins/libsnore-qt5/libsnore_backend_windowstoast.dll /export/libsnore-qt5/ && \
  cp /windows/bin/SnoreToast.exe /export && \
  cp -r /windows/plugins/iconengines /export && \
  cp -r /windows/plugins/imageformats /export && \
  cp -r /windows/plugins/platforms /export

mkdir -p /debug_export

cd "$_HOME_"/buildscripts/
cp -v download/download_mingw_debug_scripts.sh /build/download/download_mingw_debug_scripts.sh
mkdir -p /src/mingw-debug-scripts && \
  cd /src/mingw-debug-scripts && \
  /build/download/download_mingw_debug_scripts.sh  && \
  sed -i "s|your-app-name.exe|qtox.exe|g" debug-*.bat && \
  cp -a debug-*.bat /debug_export && \
  rm -fr /src/mingw-debug-scripts

cd "$_HOME_"/buildscripts/
cp -v download/download_gmp.sh /build/download/download_gmp.sh
cp -v build_gmp_windows.sh /build/build_gmp_windows.sh
mkdir -p /src/gmp && \
  cd /src/gmp && \
  /build/build_gmp_windows.sh --arch ${SCRIPT_ARCH} && \
  rm -fr /src/gmp

cd "$_HOME_"/buildscripts/
cp -v download/download_libexpat.sh /build/download/download_libexpat.sh
cp -v build_libexpat_windows.sh /build/build_libexpat_windows.sh
mkdir -p /src/libexpat && \
  cd /src/libexpat && \
  /build/build_libexpat_windows.sh --arch ${SCRIPT_ARCH} && \
  rm -fr /src/libexpat

cd "$_HOME_"/buildscripts/
cp -v download/download_gdb.sh /build/download/download_gdb.sh
cp -v build_gdb_windows.sh /build/build_gdb_windows.sh
mkdir -p /src/gdb && \
  cd /src/gdb && \
  /build/build_gdb_windows.sh --arch ${SCRIPT_ARCH} && \
  rm -fr /src/gdb && \
  cp /windows/bin/gdb.exe /debug_export/gdb.exe

df -h
mkdir -p /export/

