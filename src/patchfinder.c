#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <mach-o/loader.h>
#include <mach/thread_status.h>

#include <macho.h>
#include <patchfinder.h>

static uint64_t pf_get_kernel_base(patchfinder_t* pf) {
    uint64_t base = macho_get_base_addr(pf->kernelcache, "__TEXT");
    pf->kernelBase = base;
    return pf->kernelBase;
}

static uint64_t pf_get_kernel_entry(patchfinder_t* pf) {
    macho_enumerate_load_cmds(pf->kernelcache, ^(struct load_command* load_cmd, void* cmd, bool* stop) {
        if(load_cmd->cmd == LC_UNIXTHREAD) {
            uint8_t* load_cmd_data = ((uint8_t*)load_cmd + sizeof(struct thread_command));
            if(*(uint32_t*)load_cmd_data == ARM_THREAD_STATE64) {
                arm_thread_state64_t* state = (arm_thread_state64_t*)(load_cmd_data + 8);
                pf->kernelEntry = (uint64_t)state->__pc;
                *stop = true;
            }
        }
    });
    return pf->kernelEntry;
}

int pf_init_info(void) {
    gKPF.kernelBase = pf_get_kernel_base(&gKPF);
    gKPF.kernelEntry = pf_get_kernel_entry(&gKPF);
    const char* arch = macho_get_arch(gKPF.kernelcache);
    if(strcmp(arch, "arm64e") == 0) gKPF.isArm64e = true;
    gKPF.isArm64e = false;
    return 0;
}