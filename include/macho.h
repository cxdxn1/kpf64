#ifndef macho_h
#define macho_h

#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <stdbool.h>

typedef struct {
    struct segment_command_64 cmd;
    struct section_64 sections[];
} __attribute__((__packed__)) segment_t;

typedef struct {
    void* macho;
    size_t size;
    uint32_t magic;
    struct mach_header_64* header;
    segment_t** segments;

    uint32_t numSegments;
    uint32_t numSections;
    uint32_t numSymbols;
} macho_t;

const char* macho_get_arch(macho_t* macho);
uint32_t macho_get_magic(macho_t* macho);
const char* macho_load_cmd_to_str(uint32_t cmd);

struct load_command* macho_increment_load_cmd(struct load_command* cmd);
int macho_enumerate_load_cmds(macho_t* macho, void(^block)(struct load_command* load_cmd, void* cmd, bool* stop));
int macho_enumerate_segments(macho_t* macho, void(^block)(struct segment_command_64* segment, bool* stop));
bool macho_has_symtab(macho_t* macho, struct symtab_command* symtab);
int macho_enumerate_symbols(macho_t* macho, void(^block)(struct nlist_64* symbol, const char* name, bool* stop));
uint64_t macho_get_base_addr(macho_t* macho, char* segname);

#endif /* macho_h */