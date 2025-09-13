#ifndef arm64_h 
#define arm64_h

#include <stdint.h>

uint64_t arm64_decode_add_insn(uint32_t insn, uint64_t addr);
uint64_t arm64_decode_adr_insn(uint32_t insn, uint64_t addr);
uint64_t arm64_decode_adrp_insn(uint32_t insn, uint64_t addr);

#endif /* arm64_h */