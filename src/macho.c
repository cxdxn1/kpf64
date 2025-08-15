#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#include <macho.h>

const char* macho_get_arch(macho_t* macho) {
    switch (macho->header->cputype) {
        case CPU_TYPE_ARM64:
            if (macho->header->cpusubtype == CPU_SUBTYPE_ARM64E) return "arm64e";
                return "arm64";
        case CPU_TYPE_ARM: return "arm32";
        case CPU_TYPE_X86_64: return "x86_64";
        case CPU_TYPE_X86: return "x86";
        default: return "Unknown arch";
    }
}

uint32_t macho_get_magic(macho_t* macho) {
    macho->magic = *(uint32_t*)macho->macho;
    return macho->magic;
}

struct load_command* macho_increment_load_cmd(struct load_command* cmd) {
    if(cmd->cmdsize == 0) return NULL;
    return (struct load_command*)((uint8_t*)cmd + cmd->cmdsize);
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
        default: return "LC_UNKNOWN";
    }
}

int macho_enumerate_load_cmds(macho_t* macho, void(^block)(struct load_command* load_cmd, void* cmd, bool* stop)) {
    struct load_command* load_cmd = (struct load_command*)((uint8_t*)macho->macho + sizeof(struct mach_header_64));
    bool stop = false;
    for(int i = 0; i < macho->header->ncmds; i++) {
        uint8_t* cmd = malloc(load_cmd->cmdsize);
        memcpy(cmd, (uint8_t*)load_cmd, load_cmd->cmdsize);
        block(load_cmd, (void*)cmd, &stop);
        if(stop == true) break;
        load_cmd = macho_increment_load_cmd(load_cmd);
    }
    return 0;
}

int macho_parse_segments(macho_t* macho) {
    macho_enumerate_load_cmds(macho, ^(struct load_command *load_cmd, void *cmd, bool *stop) {
        if(load_cmd->cmd == LC_SEGMENT_64) {
            macho->numSegments++;
            if(macho->segments == NULL) {
                macho->segments = malloc(macho->numSegments * sizeof(segment_t*));
            } else {
                macho->segments = realloc(macho->segments, macho->numSegments * sizeof(segment_t*));
            }
        }
    });
    return 0;
}

int macho_enumerate_segments(macho_t* macho, void(^block)(struct segment_command_64* segment, bool* stop)) {
    struct segment_command_64* segment;
    macho->numSegments = segment->nsects;
    for(int i = 0; i < macho->numSegments; i++) {
        bool stop = false;
        block(&macho->segments[i]->cmd, &stop);
        if(stop == true) break;
    }
    return 0;
}

bool macho_has_symtab(macho_t* macho, struct symtab_command* symtab) {
    __block bool found = false;
    macho_enumerate_load_cmds(macho, ^(struct load_command* load_cmd, void* cmd, bool* stop) {
        if (load_cmd->cmd == LC_SYMTAB) {
            memcpy(symtab, cmd, sizeof(struct symtab_command));
            found = true;
            *stop = true;
        }
    });
    return found;
}

int macho_enumerate_symbols(macho_t* macho, void(^block)(struct nlist_64* symbol, const char* name, bool* stop)) {
    struct symtab_command symtab;
    macho_has_symtab(macho, &symtab);
    struct nlist_64* symbol_table = (struct nlist_64*)((uint8_t*)macho->macho + symtab.symoff);
    const char* string_table = (const char*)macho->macho + symtab.stroff;
    bool stop = false;
    for (uint32_t i = 0; i < symtab.nsyms; i++) {
        struct nlist_64* symbol = &symbol_table[i];
        const char* name = string_table + symbol->n_un.n_strx;
        block(symbol, name, &stop);
        if (stop) break;
    }
    return 0;
}

uint64_t macho_get_base_addr(macho_t* macho, char* segname) {
    __block uint64_t vmaddr = 0;
    macho_enumerate_load_cmds(macho, ^(struct load_command* load_cmd, void* cmd, bool* stop) {
        if(load_cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64* segment = (struct segment_command_64*)cmd;
            if(strncmp(segment->segname, segname, sizeof(segment->segname)) == 0) {
                vmaddr = segment->vmaddr;
                *stop = true;
            }
        }   
    });
    return vmaddr;
}