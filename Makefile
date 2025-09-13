cc = clang
include_dir = src/include
src_dir = $(wildcard src/*.c)

lib_include_dir = lib/include
lib = lib/libkpf64.a

all: kpf64

kpf64: $(src_dir) $(lib)
	$(cc) -g -I$(lib_include_dir) -I$(include_dir) -o $@ $(src_dir) $(lib)

clean:
	rm -f kpf64

.PHONY: all clean
