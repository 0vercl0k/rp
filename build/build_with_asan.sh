#!/bin/bash

# build rp with asan
PATH_CLANG_LINUX=../../asan/asan_clang_Linux/bin
SRC_RP=../src
INC_RP=../src/inc
INC_BEA=../lib/beaengine64/inc/
LIB_BEA=../lib/beaengine64/bin/BeaEngine64.a
OUT=../bin/

$PATH_CLANG_LINUX/clang++ -faddress-sanitizer -O1 -fno-omit-frame-pointer -g $SRC_RP/*.cpp -I $INC_RP -I $INC_BEA $LIB_BEA -o $OUT/asan_rp