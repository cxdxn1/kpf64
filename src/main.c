#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lib/macho.h>
#include <lib/patchfinder.h>
#include <lib/arm64.h>
#include <lib/file.h>

#include <kernel.h>
#include <patches/amfi.h>

int main(int argc, char** argv) {
    if (argc < 3) {
        printf("[*] Usage: %s <kernelcache> <patched-kernelcache>\n", argv[0]);
        return -1;
    }

    printf("[*] Starting...\n");
    const char* path = argv[1];
    const char* patchedPath = argv[2];
    int ret = file_open(path, &gKPF.kernelcache, &gKPF.kernelSize, &gKPF.kernelHeader);
    if(ret != 0) {
        printf("[!] Failed to open kernelcache\n");
        return -1;
    }
    printf("[*] Loaded kernelcache at 0x%llx with size %zu bytes\n", (uint64_t)gKPF.kernelcache, gKPF.kernelSize);

    const char* arch = macho_get_arch(gKPF.kernelcache, gKPF.kernelHeader);
    uint32_t magic = macho_get_magic(gKPF.kernelcache);
    if(strcmp(arch, "Unknown") == 0 || magic != MH_MAGIC_64) {
        printf("[*] Kernelcache is invalid or compressed, cannot continue");
        return -1;
    };
    printf("[*] Kernelcache is %s\n", arch);
    printf("[*] Magic: 0x%x\n", magic);
    printf("[*] Number of load commands: %d\n", gKPF.kernelHeader->ncmds);
    
    struct symtab_command symtab;
    if (macho_has_symtab(gKPF.kernelcache, &symtab) == true) {
        printf("[*] Found %u symbols\n", symtab.nsyms);
    } else {
        printf("[!] Kernelcache is stripped\n");
    }

    kernel_init_info();
    printf("[*] Kernel base: 0x%llx\n", gKPF.kernelBase);
    printf("[*] Found kernel __text section at 0x%llx\n", gKPF.kernelTextSection->addr);
    printf("[*] Found kernel __data section at 0x%llx\n", gKPF.kernelDataSection->addr);
    printf("[*] Found kernel __cstring section at 0x%llx\n", gKPF.kernelCstringSection->addr);
    printf("[*] Found kernel __info section at 0x%llx\n", gKPF.kernelPrelinkInfoSection->addr);
    printf("[*] Found Darwin kernel version: %s\n", gKPF.darwinVersion);
    printf("[*] Found XNU version: %s\n", gKPF.xnuVersion);

    void* darwin_version_addr = memmem(gKPF.kernelcache, gKPF.kernelSize, "Darwin Kernel Version", strlen("Darwin Kernel Version"));
    uint64_t fileoff = (uint8_t*)darwin_version_addr - (uint8_t*)gKPF.kernelcache;
    uint64_t va = macho_translate_fileoff_to_va(gKPF.kernelcache, fileoff);

    // Test for pf_xref64
    // uint64_t xref = pf_xref64(gKPF.kernelcache, gKPF.kernelTextSection, va);
    // if (xref == 0) return -1;
    // printf("[*] Found Darwin Kernel Version string ref at 0x%llx\n", va); // 0xfffffff00701f648

    printf("[*] Initialising AMFI patch...\n");
    int patch = kernel_amfi_is_cd_in_trustcache_patch();
    if(patch != 0) {
        printf("[!] AMFI patch failed\n");
        return -1;
    }

    file_write(patchedPath, gKPF.kernelcache, gKPF.kernelSize);
    file_close(gKPF.kernelcache);
    printf("[*] Wrote patches to %s\n", patchedPath);
    return 0;
}