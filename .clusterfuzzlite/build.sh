#!/bin/bash -eu

$CXX $CXXFLAGS -std=c++17 \
  $SRC/fuzzing-farm/src/victima.c \
  $SRC/fuzzing-farm/src/harness.cc \
  -I$SRC/fuzzing-farm/src \
  $LIB_FUZZING_ENGINE \
  -o $OUT/fuzzer_victima
