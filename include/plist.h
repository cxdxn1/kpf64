#ifndef plist_h
#define plist_h

#include <stdint.h>

uint64_t plist_parse_integer(void *key);
uint64_t plist_parse_prelink_info(void* macho, struct section_64* kmod_info, char* bundle_name);
uint64_t plist_get_kext_size(void* macho, struct section_64* kmod_info, char* bundle_name);

#endif /* plist_h */