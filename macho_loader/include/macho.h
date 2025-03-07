#ifndef macho_h
#define macho_h

#include <mach-o/loader.h>

struct macho {
    struct mach_header_64 mh64;
    struct load_command lc;
    struct uuid_command uuid;
    struct segment_command_64 sc64;
    struct section_64 s64;
    struct symtab_command sc;
};

struct sectionInfo {
    uint64_t addr;
    size_t size;
};

struct segmentInfo {
    uint64_t addr;
    size_t size;
};

#endif /* macho_h */