#! /bin/bash

_HOME2_=$(dirname $0)
export _HOME2_
_HOME_=$(cd $_HOME2_;pwd)
export _HOME_

echo $_HOME_
cd $_HOME_


if [ "$1""x" == "buildx" ]; then
    cp -a ../buildscripts .
    cd ./buildscripts/
    docker build -f docker/Dockerfile.ubuntu_for_appimage -t qtox_appimage001 .
    exit 0
fi

build_for="appimage"

for system_to_build_for in $build_for ; do

    system_to_build_for_orig="$system_to_build_for"
    system_to_build_for=$(echo "$system_to_build_for_orig" 2>/dev/null|tr ':' '_' 2>/dev/null)

    cd $_HOME_/
    mkdir -p $_HOME_/"$system_to_build_for"/

    mkdir -p $_HOME_/"$system_to_build_for"/artefacts
    mkdir -p $_HOME_/"$system_to_build_for"/script
    mkdir -p $_HOME_/"$system_to_build_for"/workspace

    ls -al $_HOME_/"$system_to_build_for"/

    rsync -a ../ --exclude=.localrun $_HOME_/"$system_to_build_for"/workspace/build
    chmod a+rwx -R $_HOME_/"$system_to_build_for"/workspace/build

    echo '#! /bin/bash

cp -a /workspace/build/. /qtox/
./appimage/build.sh --src-dir /qtox

ls -alR *x86_64.AppImage || echo "ignore error"

cp -av /qtox/qTox-.x86_64.AppImage /artefacts/qTox-.x86_64.AppImage || exit 1
chmod a+rwx /artefacts/*

' > $_HOME_/"$system_to_build_for"/script/run.sh

    docker run -ti --rm \
      -v $_HOME_/"$system_to_build_for"/artefacts:/artefacts \
      -v $_HOME_/"$system_to_build_for"/script:/script \
      -v $_HOME_/"$system_to_build_for"/workspace:/workspace \
      --net=host \
      --privileged \
     "qtox_appimage001" \
     /bin/sh -c "apk add bash >/dev/null 2>/dev/null; /bin/bash /script/run.sh"
     if [ $? -ne 0 ]; then
        echo "** ERROR **:$system_to_build_for_orig"
        exit 1
     else
        echo "--SUCCESS--:$system_to_build_for_orig"
     fi

done


