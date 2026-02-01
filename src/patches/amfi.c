#include <lib/macho.h>
#include <lib/patchfinder.h>
#include <lib/file.h>
#include "plist.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include <patches/amfi.h>
#include <kernel.h>

typedef struct {
    uint64_t fileoff;
    void* base;
    size_t size;
    struct mach_header_64* header;
    struct section_64* textSection;
} amfi_kext_t;

static void kernel_get_amfi_kext_info(amfi_kext_t* kext) {
    kext->fileoff = kernel_find_kext(gKPF.kernelcache, "com.apple.driver.AppleMobileFileIntegrity");
    kext->base = gKPF.kernelcache + kext->fileoff;
    kext->size = (size_t)plist_get_kext_size(gKPF.kernelcache, gKPF.kernelPrelinkInfoSection, "com.apple.driver.AppleMobileFileIntegrity");
    kext->header = (struct mach_header_64*)((uint8_t*)gKPF.kernelcache + kext->fileoff);
    kext->textSection = pf_find_section(kext->header, "__TEXT_EXEC", "__text");
}

// Patch AMFIIsCodeDirectoryInTrustCache to always return true
int kernel_amfi_is_cd_in_trustcache_patch(void) {
    amfi_kext_t kext;
    kernel_get_amfi_kext_info(&kext);
    uint64_t mov_w8_0x13_addr = pf_step64(kext.base, kext.textSection, kext.size, 0x52800268, 0xFFFFFFFF);
    if(!mov_w8_0x13_addr) return -1;
    printf("[*] Found MOV W8 #0X13 at 0x%llx\n", mov_w8_0x13_addr);

    uint64_t func_start = mov_w8_0x13_addr - 0x34;
    printf("[*] Found AMFIIsCodeDirectoryInTrustCache function start at 0x%llx\n", func_start);

    uint64_t func_start_fileoff = macho_translate_va_to_fileoff(gKPF.kernelcache, func_start);
    uint32_t* insn = (uint32_t*)((uint8_t*)gKPF.kernelcache + func_start_fileoff);
    insn[0] = 0xD2800020; // mov x0, #1
    insn[1] = 0xD65F03C0; // ret

    printf("[*] Patched AMFIIsCodeDirectoryInTrustCache function start to MOV X0 #1, RET at 0x%llx\n", func_start);
    return 0;
}