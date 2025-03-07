#include <macho.h>
#include <stdio.h>
#include <string.h>

static void macho_store_section64_info(const char* sectName, uint64_t addr, size_t size) {
    struct sectionInfo* info;
    unsigned char nameTruncated[17]; // section64 (16 bytes) + \0 (1 byte)
    memset(nameTruncated, 0, sizeof(nameTruncated));
}

// Get the lowest 8 bits of the section flags and see if they contain any stubs
static void macho_get_section64_stubs(struct macho* macho) {
    if((macho->s64.flags & 0xFF) == S_SYMBOL_STUBS) { 
        printf('[*] Section contains symbol stubs\n');
    }

    printf("[*] Section contains no stubs\n");
}

int macho_process_section64(struct macho* macho) {
    uint64_t* section_load_vaddr = NULL;
    printf("[*] section64: %s\n", macho->s64.sectname);
    macho_get_section64_stubs(macho);
}

