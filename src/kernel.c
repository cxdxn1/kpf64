#include <string.h>
#include <lib/patchfinder.h>
#include <lib/macho.h>

#include <kernel.h>
#include <plist.h>

kpf_info_t gKPF = { 0 };

static const char* kernel_find_darwin_version(void) {
    const char* string = pf_find_string_data(gKPF.kernelcache, "__TEXT", "__const", "Darwin Kernel Version");
    if (string == NULL) return NULL;
    static char darwinVersion[128];
    if (sscanf(string, "Darwin Kernel Version %7[^:]", darwinVersion) == 0) return NULL;

    return darwinVersion;
}

static const char* kernel_find_xnu_version(void) {
    const char* string = pf_find_string_data(gKPF.kernelcache, "__TEXT", "__const", "Darwin Kernel Version");
    if (string == NULL) return NULL;
    static char xnuVersion[64];

    const char* cursor = strstr(string, "root:xnu-");
    if (cursor == NULL) return NULL;
    if (sscanf(cursor, "root:%63[^/;]", xnuVersion) == 0) return NULL;

    return xnuVersion;
}

uint64_t kernel_strip_xnu_va_tag(uint64_t va) {
    uint64_t tag_bits = (va >> 32) & 0xFFFF;
    uint64_t untagged_va = (0xFFFFULL << 48) | va;
    if(tag_bits == 0xFFF0) return untagged_va;
    else return va; // not tagged
}

uint64_t kernel_find_kext(void* macho, char* kextName) {
    struct segment_command_64* prelink_info = macho_get_segment_by_segname(macho, "__PRELINK_INFO");
    if(!prelink_info) return 0;
    struct section_64* info = macho_get_section_by_sectname(macho, prelink_info, "__info");
    if(!info) return 0;
    
    uint64_t kext_fileoff = plist_parse_prelink_info(macho, info, kextName);
    return kext_fileoff;
}

void kernel_init_info(void) {
    gKPF.kernelBase = macho_get_base_addr(gKPF.kernelcache);
    gKPF.darwinVersion = kernel_find_darwin_version();
    gKPF.xnuVersion = kernel_find_xnu_version();
    // gKPF.osVersion = kernel_find_os_version();
    gKPF.kernelTextSection = pf_find_section(gKPF.kernelcache, "__TEXT_EXEC", "__text");
    gKPF.kernelDataSection = pf_find_section(gKPF.kernelcache, "__DATA", "__data");
    gKPF.kernelCstringSection = pf_find_section(gKPF.kernelcache, "__TEXT", "__cstring");
    gKPF.kernelPrelinkInfoSection = pf_find_section(gKPF.kernelcache, "__PRELINK_INFO", "__info");
}