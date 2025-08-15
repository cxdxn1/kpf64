#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <macho.h>
#include <patchfinder.h>

patchfinder_t gKPF = { 0 };

int main(int argc, char** argv) {
    if(argc < 2) {
        printf("[*] Usage: %s <path to kernelcache>\n", argv[0]);
        return -1;
    }

    const char* path = argv[1];
    FILE* fp = fopen(path, "rb");
    if(!fp) return -1;

    fseek(fp, 0, SEEK_END);
    size_t len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    void* buf = malloc(len);
    if(!buf) return -1;
    fread(buf, 1, len, fp);
    fclose(fp);

    gKPF.kernelcache = malloc(sizeof(macho_t));
    if(!gKPF.kernelcache) return -1;

    gKPF.kernelcache->macho = buf;
    gKPF.kernelcache->size = len;
    gKPF.kernelcache->header = (struct mach_header_64*)buf;

    printf("[*] Loaded MachO at 0x%llx with size %zu bytes\n", (uint64_t)buf, gKPF.kernelcache->size);

    const char* arch = macho_get_arch(gKPF.kernelcache);
    uint32_t magic = macho_get_magic(gKPF.kernelcache);
    printf("[*] MachO is %s\n", arch);
    printf("[*] Magic: 0x%x\n", magic);
    printf("[*] Number of load commands: %d\n", gKPF.kernelcache->header->ncmds);
    printf("[*] Parsing load commands...\n");
    macho_enumerate_load_cmds(gKPF.kernelcache, ^(struct load_command* load_cmd, void* cmd, bool* stop) {
        if(load_cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64* segment = (struct segment_command_64*)cmd;
            printf("[*] Found %s segment with segname %s at 0x%llx\n", macho_load_cmd_to_str(load_cmd->cmd), segment->segname, segment->fileoff);
        } else {
            printf("[*] Found %s load command\n", macho_load_cmd_to_str(load_cmd->cmd));
        }
    });

    struct symtab_command symtab;
    if(macho_has_symtab(gKPF.kernelcache, &symtab)) {
        printf("[*] Found %u symbols\n", symtab.nsyms);
    } else {
        printf("[*] Binary is stripped\n");
    }

    macho_enumerate_symbols(gKPF.kernelcache, ^(struct nlist_64* symbol, const char* name, bool* stop) {
        printf("[*] Symbol: %s\n", name);
    });

    printf("[*] Parsing kernel info...\n");
    pf_init_info();
    printf("[*] Kernel base: 0x%llx\n", gKPF.kernelBase);
    printf("[*] Kernel entry: 0x%llx\n", gKPF.kernelEntry);
    return 0;
}