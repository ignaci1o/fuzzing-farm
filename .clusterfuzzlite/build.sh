#!/bin/bash -eu

$CC $CFLAGS -c $SRC/fuzzing-farm/src/victima.c -o $SRC/victima.o

$CXX $CXXFLAGS -std=c++17 \
  $SRC/fuzzing-farm/src/harness.cc \
  $SRC/victima.o \
  $LIB_FUZZING_ENGINE \
  -o $OUT/fuzzer_victima
