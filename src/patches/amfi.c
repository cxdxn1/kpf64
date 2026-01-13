#include <lib/macho.h>
#include <lib/patchfinder.h>
#include "plist.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include <patches/amfi.h>
#include <kernel.h>

// NOTE: move this to an src/patches dir when we have other patches

typedef struct {
    uint64_t fileoff;
    // void* base;
    size_t size;
    struct mach_header_64* header;
    struct section_64* amfiTextSection;
} amfi_kext_t;

void kernel_get_amfi_kext_info(amfi_kext_t* kext) {
    kext->fileoff = kernel_find_kext(gKPF.kernelcache, "com.apple.driver.AppleMobileFileIntegrity");
    // kext->base = gKPF.kernelcache + kext->fileoff;
    kext->size = (size_t)plist_get_kext_size(gKPF.kernelcache, gKPF.kernelPrelinkInfoSection, "com.apple.driver.AppleMobileFileIntegrity");
    kext->header = (struct mach_header_64*)((uint8_t*)gKPF.kernelcache + kext->fileoff);
    kext->amfiTextSection = pf_find_section(kext->header, "__TEXT_EXEC", "__text");
}

// Shellcode from g0blin
// Sets amfiret mov w0 #1 to mov x0 xzr and restores stack + registers
static const uint32_t amfiret_shc[] = {
    0x18000148, // ldr w8, 0x28
    0xb90002e8, // str w8, [x23]
    0xaa1f03e0, // mov x0, xzr
    0xa9477bfd, // ldp x29, x30, [sp, #112]
    0xa9464ff4, // ldp x20, x19, [sp, #96]
    0xa94557f6, // ldp x22, x21, [sp, #80]
    0xa9445ff8, // ldp x24, x23, [sp, #64]
    0xa94367fa, // ldp x26, x25, [sp, #48]
    0x910203ff, // add sp, sp, #128
    0xd65f03c0, // ret
    0x0e00400f  // tbl.8b v15, { v0, v1, v2 }, v0
};

amfi_kext_t gAMFI = { 0 };

// r2 -e io.cache=true -w -s 0xfffffff00650c42c kernelcache.release.iphone6.raw
int kernel_patch_amfiret(void) {
    void* amfi_hook_execve_str = memmem(gKPF.kernelcache, gKPF.kernelSize, "AMFI: hook..execve() killing pid %u: %s\n", strlen("AMFI: hook..execve() killing pid %u: %s\n")); // 0xfffffff0061ab62b
    if (amfi_hook_execve_str == NULL) {
        printf("[!] Could not find AMFI hook execve string\n");
        return -1;
    }

    kernel_get_amfi_kext_info(&gAMFI);
    uint64_t fileoff = (uint8_t*)amfi_hook_execve_str - (uint8_t*)gKPF.kernelcache;
    uint64_t va = macho_translate_fileoff_to_va(gKPF.kernelcache, fileoff);
    printf("[*] AMFI kext fileoff at 0x%llx\n", gAMFI.fileoff);
    printf("[*] AMFI kext VA at 0x%llx\n", macho_translate_fileoff_to_va(gKPF.kernelcache, gAMFI.fileoff));
    printf("[*] Found AMFI hook execve string at fileoff 0x%llx\n", fileoff);
    // printf("[*] Found AMFI hook execve string at VA 0x%llx\n", va);
    uint64_t adrp_insn = pf_xref64(gKPF.kernelcache, gAMFI.amfiTextSection, va); // 0xfffffff00650c370
    printf("[*] Found AMFI hook execve string xref at ADRP 0x%llx\n", adrp_insn);
    
    uint64_t amfiret = pf_step64(gKPF.kernelcache, gAMFI.amfiTextSection, adrp_insn, RET_INSN_OPC); // 0xfffffff00650c42c
    if(amfiret == 0) return -1;
    printf("[*] Found AMFI RET at 0x%llx\n", amfiret);

    uint32_t* patch_addr = (uint32_t*)(gKPF.kernelcache + amfiret - 8);
    void* ret = memcpy((uint8_t*)patch_addr, amfiret_shc, sizeof(amfiret_shc));
    if(ret != patch_addr) return -1;
    printf("[*] Patched AMFI RET mov w0, #1 to mov x0, xzr at %p\n", patch_addr);

    return 0;
}