#!/usr/bin/bash -ex

docker image inspect tdx-module-docker >/dev/null || {
    docker build . -t tdx-module-docker
}

[ -d libs/ipp/ipp-crypto-ipp-crypto_2021_10_0 ] || {
    mkdir -p libs/ipp
    git clone -b ippcp_2021.10.0 --depth=1 https://github.com/intel/ipp-crypto libs/ipp/ipp-crypto-ipp-crypto_2021_10_0
}

docker run -itd -v $PWD:$PWD -w $PWD --name tdx-module-docker tdx-module-docker
docker exec tdx-module-docker bash -c \
    "cd libs/ipp/ipp-crypto-ipp-crypto_2021_10_0 && \
    CC=clang CXX=clang++ cmake CMakeLists.txt -B_build -DARCH=intel64 -DMERGED_BLD:BOOL=off -DNO_CRYPTO_MB:BOOL=TRUE -DPLATFORM_LIST=l9 -DIPPCP_CUSTOM_BUILD=\"IPPCP_AES_ON;IPPCP_CLMUL_ON;IPPCP_VAES_ON;IPPCP_VCLMUL_ON;\" && \
    cd _build && \
    make -j8 ippcp_s_l9"

if [ -d venv ];
then
    source venv/bin/activate
else
    python -m venv venv
    source venv/bin/activate
    pip3 install click pyelftools pycryptodome python-cpuid
fi

defined_vars=""
bindir=bin/debug
objdump_options="-D "
if [ ! -z $OPENTDX ]
then
    defined_vars+="OPENTDX=1 "
fi
if [ ! -z $DEBUGTRACE ]
then
    defined_vars+="DEBUGTRACE=1 "
fi
if [ ! -z $UNSTRIPPED ]
then
    defined_vars+="UNSTRIPPED=1 "
    bindir=bin/debug.unstripped
    objdump_options+="-S "
fi

docker exec tdx-module-docker bash -c \
    "make ${defined_vars} clean && \
     bear make -j DEBUG=1 TDX_MODULE_BUILD_DATE=20240407 TDX_MODULE_BUILD_NUM=744 TDX_MODULE_UPDATE_VER=6 ${defined_vars}"

objdump ${objdump_options} ${bindir}/libtdx.so > ${bindir}/libtdx.dump

if [ -z $UNSTRIPPED ]
then
    ./gen_sigstruct --mode w -m ${bindir}/libtdx.so -p tdx-module.privkey.PEM
fi

docker kill tdx-module-docker
docker rm tdx-module-docker
