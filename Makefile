cc = clang
src_dir = $(wildcard src/*.c)

all: kpf

kpf: $(src_dir)
	$(cc) -g -Iinclude -o kpf $(src_dir)

.PHONY: all clean
