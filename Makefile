cc = clang
include_dir = include
src_dir = $(wildcard src/*.c)
patches_include_dir = include/patches
patches_src_dir = $(wildcard src/patches/*.c)

lib_dir = libpf64
lib = libpf64/libpf64.a

all: kpf64

kpf64: $(src_dir) $(lib)
	$(cc) -g -I$(lib_dir) -I$(include_dir) -I$(patches_include_dir) -o $@ $(src_dir) $(patches_src_dir) $(lib)

clean:
	rm -f kpf64

.PHONY: all clean