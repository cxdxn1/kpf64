#ifndef kernel_h
#define kernel_h

#include <lib/patchfinder.h>

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
    struct section_64* kernelPrelinkInfoSection;
} kpf_info_t;

extern kpf_info_t gKPF;

uint64_t kernel_strip_xnu_va_tag(uint64_t va);
uint64_t kernel_find_kext(void* macho, char* kextName);

void kernel_init_info(void);

#endif /* kernel_h */