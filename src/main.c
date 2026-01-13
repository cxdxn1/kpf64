#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lib/macho.h>
#include <lib/patchfinder.h>
#include <lib/arm64.h>

#include <kernel.h>
#include <patches/amfi.h>

static int open_kernelcache(const char* path, void** kernelOut, size_t* sizeOut, struct mach_header_64** headerOut) {
    FILE* fp = fopen(path, "rb");
    if (fp == NULL) return -1;
    fseek(fp, 0, SEEK_END);
    size_t len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    void* buf = malloc(len);
    if (buf == NULL) return -1;
    fread(buf, 1, len, fp);
    fclose(fp);

    *kernelOut = buf;
    *sizeOut = len;
    *headerOut = (struct mach_header_64*)buf;
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("[*] Usage: %s <path to kernelcache>\n", argv[0]);
        return -1;
    }

    printf("[*] Starting...\n");
    const char* path = argv[1];
    int ret = open_kernelcache(path, &gKPF.kernelcache, &gKPF.kernelSize, &gKPF.kernelHeader);
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

    // uint64_t xref = pf_xref64(gKPF.kernelcache, gKPF.kernelTextSection, va);
    // if (xref == 0) return -1;
    // printf("[*] Found Darwin Kernel Version string ref at 0x%llx\n", va); // 0xfffffff00701f648

    printf("[*] Initialising amfiret patch...\n");
    int patch = kernel_patch_amfiret();
    //if(patch != 0) return -1;

    free(gKPF.kernelcache);
    gKPF.kernelcache = NULL;
    return 0;
}