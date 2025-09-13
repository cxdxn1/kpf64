#ifndef kernel_h
#define kernel_h

#include <patchfinder.h>

typedef struct {
    void* kernelcache;
    size_t kernelSize;
    uint64_t kernelBase;
    const char* darwinVersion;
    const char* xnuVersion;
    const char* osVersion;
    struct mach_header_64* kernelHeader;

    struct section_64* kernelTextSection;
    struct section_64* kernelDataSection;
    struct section_64* kernelCstringSection;
} kpf_info_t;

extern kpf_info_t gKPF;

void kernel_init_info(void);

#endif /* kernel_h */