#!/usr/bin/bash

docker image inspect tdx-module-docker >/dev/null || {
    docker build . -t tdx-module_docker
}

[ -d libs/ipp/ipp-crypto-ipp-crypto_2021_10_0 ] || {
    mkdir -p libs/ipp
    git clone -b ippcp_2021.10.0 --depth=1 https://github.com/intel/ipp-crypto libs/ipp/ipp-crypto-ipp-crypto_2021_10_0
}

docker run --rm -v $PWD:$PWD -w $PWD --name tdx-module-docker tdx-module-docker
