cc = clang
include_dir = src/include
src_dir = $(wildcard src/*.c)

lib_include_dir = lib/include
lib = lib/libkpf.a

all: kpf

kpf: $(src_dir) $(lib)
	$(cc) -g -I$(lib_include_dir) -I$(include_dir) -o $@ $(src_dir) $(lib)

clean:
	rm -f kpf

.PHONY: all clean
