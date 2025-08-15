#ifndef kernel_h
#define kernel_h

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <macho.h>

typedef struct {
    macho_t* kernelcache; // Points to loaded MachO in VM
    uint64_t kernelBase;
    uint64_t kernelEntry;
    size_t kernelSize;
    bool isArm64e;

    char* xnuVersion;
    char* xnuBuild;
    char* osVersion;

    // Add section64 stuff here
} patchfinder_t;

extern patchfinder_t gKPF;

int pf_init_info(void);

#endif /* kernel_h */