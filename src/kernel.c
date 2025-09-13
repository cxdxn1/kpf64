#include <string.h>

#include "patchfinder.h"
#include <kernel.h>
#include <macho.h>

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

// DTPlatformVersion doesn't seem to exist on older kernelcaches - helper function is here anyway
static const char* kernel_find_os_version(void) {
    const char* string = pf_find_string_data(gKPF.kernelcache, "__TEXT", "__info_plist", "<key>DTPlatformVersion</key>");
    if (string == NULL) return NULL;
    static char osVersion[128];
    if (sscanf(string, "<key>DTPlatformVersion</key> %*[\t ]<string>%127[^<]</string>", osVersion) != 1) return NULL;

    return osVersion;
}

void kernel_init_info(void) {
    gKPF.kernelBase = macho_get_base_addr(gKPF.kernelcache);
    gKPF.darwinVersion = kernel_find_darwin_version();
    gKPF.xnuVersion = kernel_find_xnu_version();
    gKPF.osVersion = kernel_find_os_version();
    gKPF.kernelTextSection = pf_find_section(gKPF.kernelcache, "__TEXT_EXEC", "__text");
    gKPF.kernelDataSection = pf_find_section(gKPF.kernelcache, "__DATA", "__data");
    gKPF.kernelCstringSection = pf_find_section(gKPF.kernelcache, "__TEXT", "__cstring");
}