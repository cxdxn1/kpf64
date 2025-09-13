#include "arm64.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <mach-o/loader.h>
#include <sys/mman.h>

#include <macho.h>
#include <patchfinder.h>

struct section_64* pf_find_section(void* macho, const char* segname, const char* sectname) {
    struct segment_command_64* segment = macho_get_segment_by_segname(macho, segname);
    struct section_64* section = macho_get_section_by_sectname(macho, segment, sectname);
    if(segment == NULL) return NULL;
    if(section == NULL) return NULL;

    return section;
}

// objc string support?
uint64_t pf_find_string(void* macho, const char* segname, const char* sectname, const char* string) {
    struct section_64* section = pf_find_section(macho, segname, sectname);
    if (section == NULL) return 0;

    const uint8_t* sectionData = (const uint8_t*)macho + section->offset;
    size_t slen = strlen(string);

    for (size_t j = 0; j + slen + 1 <= section->size; j++) {
        if (memcmp(sectionData + j, string, slen) == 0) {
            uint64_t va = section->addr + j; 
            return va;
        }
    }
    return 0;
}

const char* pf_find_string_data(void* macho, const char* segname, const char* sectname, const char* string) {
    struct section_64* section = pf_find_section(macho, segname, sectname);
    if (section == NULL) return NULL;

    const char* sectionData = (const char*)macho + section->offset;
    size_t slen = strlen(string);

    for (size_t j = 0; j + slen + 1 <= section->size; j++) {
        if (memcmp(sectionData + j, string, slen) == 0) {
            const char* result = sectionData + j;
            return result;
        }
    }
    return NULL;
}

// TODO: add decoding logic for more insns
uint64_t pf_xref(void* macho, struct section_64* section, uint64_t from) {
    struct segment_command_64* segment = macho_get_segment_by_section_ptr(macho, section);
    if(segment == NULL) return -1;
    if (segment->initprot & VM_PROT_EXECUTE) {
        uint8_t* sectionData = (uint8_t*)macho + section->offset;
        for (uint64_t i = 0; i + 8 <= section->size; i += 4) {
            uint32_t insn = *(uint32_t*)(sectionData + i);
            uint64_t va = section->addr + i;

            uint64_t adrp_target = arm64_decode_adrp_insn(insn, va);
            if (adrp_target != -1) {
                uint32_t next_insn = *(uint32_t*)(sectionData + i + 4);
                uint64_t add_target = arm64_decode_add_insn(next_insn, adrp_target);

                if (add_target == from) {
                    return va;
                }
            }

            uint64_t adr_target = arm64_decode_adr_insn(insn, va);
            if(adr_target != -1) {
                if(adr_target == from) {
                    return va;
                }
            }
        }
    }
    return -1;
}

