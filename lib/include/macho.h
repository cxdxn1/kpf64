#ifndef macho_h
#define macho_h

#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <stdbool.h>

const char* macho_get_arch(void* macho, struct mach_header_64* header);
uint32_t macho_get_magic(void* macho);
size_t macho_get_size(void* macho);
const char* macho_load_cmd_to_str(uint32_t cmd);
bool macho_has_symtab(void* macho, struct symtab_command* symtab);
size_t macho_get_size(void* macho);

struct segment_command_64* macho_get_segment_by_segname(void* macho, const char* segname);
struct section_64* macho_get_section_by_sectname(void* macho, struct segment_command_64* segment, const char* sectname);
struct segment_command_64* macho_get_segment_by_section_ptr(void* macho, struct section_64* section);

uint64_t macho_get_base_addr(void* macho);
uint64_t macho_vmaddr_to_fileoff(void* macho, uint64_t vmaddr);
void macho_free(void* macho);

#endif /* macho_h */