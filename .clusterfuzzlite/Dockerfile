FROM gcr.io/oss-fuzz-base/base-builder:v1

COPY . $SRC/fuzzing-farm
WORKDIR $SRC/fuzzing-farm
COPY .clusterfuzzlite/build.sh $SRC/
