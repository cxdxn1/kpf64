#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#include <macho.h>

const char* macho_get_arch(void* macho, struct mach_header_64* header) {
    switch (header->cputype) {
        case CPU_TYPE_ARM64:
            if (header->cpusubtype == CPU_SUBTYPE_ARM64E) return "arm64e";
            else return "arm64";
        case CPU_TYPE_ARM: return "arm32";
        case CPU_TYPE_X86_64: return "x86_64";
        case CPU_TYPE_X86: return "x86";
        default: return "Unknown arch";
    }
}

uint32_t macho_get_magic(void* macho) {
    uint32_t magic = *(uint32_t*)macho;
    return magic;
}

const char* macho_load_cmd_to_str(uint32_t cmd) {
    switch(cmd) {
        case LC_SYMTAB: return "LC_SYMTAB";
        case LC_UNIXTHREAD: return "LC_UNIXTHREAD";
        case LC_SEGMENT_64: return "LC_SEGMENT_64";
        case LC_UUID: return "LC_UUID";
        case LC_CODE_SIGNATURE: return "LC_CODE_SIGNATURE";
        case LC_VERSION_MIN_IPHONEOS: return "LC_VERSION_MIN_IPHONEOS";
        case LC_FUNCTION_STARTS: return "LC_FUNCTION_STARTS";
        case LC_SOURCE_VERSION: return "LC_SOURCE_VERSION";
        case LC_BUILD_VERSION: return "LC_BUILD_VERSION";
        case LC_DYSYMTAB: return "LC_DYSYMTAB";
        case LC_DYLD_EXPORTS_TRIE: return "LC_DYLD_EXPORTS_TRIE";
        case LC_DYLD_CHAINED_FIXUPS: return "LC_DYLD_CHAINED_FIXUPS";
        case LC_FILESET_ENTRY: return "LC_FILESET_ENTRY";
        default: return "LC_UNKNOWN";
    }
}

static struct load_command* macho_increment_load_cmd(struct load_command* cmd) {
    if(cmd->cmdsize == 0) return NULL;
    return (struct load_command*)((uint8_t*)cmd + cmd->cmdsize);
}

static struct section_64* macho_increment_section(struct section_64* section) {
    if(section->size == 0) return NULL;
    return (struct section_64*)((uint8_t*)section + sizeof(struct section_64));
}

size_t macho_get_size(void* macho) {
    struct mach_header_64* header = (struct mach_header_64*)macho;
    struct load_command* loadCmd = macho + sizeof(struct mach_header_64);
    size_t size = 0;
    for(int i = 0; i < header->ncmds; i++) {
        if(loadCmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64* segment = (struct segment_command_64*)loadCmd;
            size_t end = (size_t)(segment->fileoff + segment->filesize);
            if(end > 0) size = end;
        }
        loadCmd = macho_increment_load_cmd(loadCmd);
    }
    return size;
}

struct segment_command_64* macho_get_segment_by_segname(void* macho, const char* segname) {
    struct mach_header_64* header = (struct mach_header_64*)macho;
    struct load_command* loadCmd = (struct load_command*)((uint8_t*)macho + sizeof(struct mach_header_64));
    for(int i = 0; i < header->ncmds; i++) {
        if(loadCmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64* segment = (struct segment_command_64*)loadCmd;
            if(strcmp(segment->segname, segname) == 0) return segment;
        }
        loadCmd = macho_increment_load_cmd(loadCmd);
    }
    return NULL;
}

struct section_64* macho_get_section_by_sectname(void* macho, struct segment_command_64* segment, const char* sectname) {
    struct section_64* section = (struct section_64*)((uint8_t*)segment + sizeof(struct segment_command_64));
    for(int i = 0; i < segment->nsects; i++) {
        if(strcmp(section->sectname, sectname) == 0) return section;
        section = macho_increment_section(section);
    }
    return NULL;
}

struct segment_command_64* macho_get_segment_by_section_ptr(void* macho, struct section_64* section) {
    struct mach_header_64* header = (struct mach_header_64*)macho;
    struct load_command* loadCmd = (struct load_command*)((uint8_t*)macho + sizeof(struct mach_header_64));
    for(int i = 0; i < header->ncmds; i++) {
        struct segment_command_64* segment = (struct segment_command_64*)loadCmd;
        struct section_64* sections = (struct section_64*)((uint8_t*)segment + sizeof(struct segment_command_64));
        for(int j = 0; j < segment->nsects; j++) {
            if(&sections[j] == section) return segment;
        }
        loadCmd = macho_increment_load_cmd(loadCmd);
    }
    return NULL;
}

uint64_t macho_get_base_addr(void* macho) {
    struct segment_command_64* textSegment = macho_get_segment_by_segname(macho, "__TEXT");
    return textSegment->vmaddr;
}

bool macho_has_symtab(void* macho, struct symtab_command* symtab) {
    struct mach_header_64* header = (struct mach_header_64*)macho;
    struct load_command* loadCmd = (struct load_command*)((uint8_t*)macho + sizeof(struct mach_header_64));
    for(int i = 0; i < header->ncmds; i++) {
        if (loadCmd->cmd == LC_SYMTAB) {
            memcpy(symtab, loadCmd, sizeof(struct symtab_command));
            return true;
        }
        loadCmd = macho_increment_load_cmd(loadCmd);
    }
    return false;
}