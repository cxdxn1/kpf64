#include <mach-o/loader.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <lib/macho.h>

#include <plist.h>

uint64_t plist_parse_integer(void *key) {
    char* key_value = strstr(key, "<integer");
    if (key_value != NULL) {
        key_value = strstr(key_value, ">");
        if (key_value != NULL) {
            return strtoull(key_value + 1, 0, 0);
        }
    }
    return 0;
}

uint64_t plist_parse_prelink_info(void* macho, struct section_64* kmod_info, char* bundle_name) {
    char kextName[256];
    char* start = macho + kmod_info->offset;
    char* info_dict = strstr(start, "PrelinkInfoDictionary");
    char* last_dict = strstr(info_dict, "<array>") + 7;

    while (last_dict != NULL) {
        char* dict_end = strstr(last_dict, "</dict>");
        if (!dict_end) break;

        char* dict2 = strstr(last_dict + 1, "<dict>");
        while (dict2 != NULL) {
            if (dict2 > dict_end) break;
            dict2 = strstr(dict2 + 1, "<dict>");
            dict_end = strstr(dict_end + 1, "</dict>");
        }

        char* bundleID = strstr(last_dict, "CFBundleIdentifier");

        if (bundleID != NULL) {
            char* value_key = strstr(bundleID, "<string>");
            if (value_key != NULL) {
                value_key += strlen("<string>");
                char* key_end = strstr(value_key, "</string>");
                if (key_end != NULL) {
                    uint32_t key_len = key_end - value_key;
                    memcpy(kextName, value_key, key_len);
                    kextName[key_len] = 0;
                    if (strcmp(kextName, bundle_name) == 0) {
                        char* addr_key = strstr(last_dict, "_PrelinkExecutableLoadAddr");
                        if (addr_key != NULL) {
                            uint64_t va = plist_parse_integer(addr_key);
                            uint64_t fileoff = macho_translate_va_to_fileoff(macho, va);
                            return fileoff;
                        }

                    }
                }
            }
        }
        last_dict = strstr(dict_end, "<dict>"); // Increment dict
    }
    return 0;
}

uint64_t plist_get_kext_size(void* macho, struct section_64* kmod_info, char* bundle_name) {
    char kextName[256];
    char* start = macho + kmod_info->offset;
    char* info_dict = strstr(start, "PrelinkInfoDictionary");
    if (!info_dict) return 0;

    char* last_dict = strstr(info_dict, "<array>") + 7;
    while (last_dict != NULL) {
        char* dict_end = strstr(last_dict, "</dict>");
        if (!dict_end) break;

        char* dict2 = strstr(last_dict + 1, "<dict>");
        while (dict2 != NULL) {
            if (dict2 > dict_end) break;
            dict2 = strstr(dict2 + 1, "<dict>");
            dict_end = strstr(dict_end + 1, "</dict>");
        }

        char* bundleID = strstr(last_dict, "CFBundleIdentifier");
        if (bundleID != NULL) {
            char* value_key = strstr(bundleID, "<string>");
            if (value_key != NULL) {
                value_key += strlen("<string>");
                char* key_end = strstr(value_key, "</string>");
                if (key_end != NULL) {
                    uint32_t key_len = key_end - value_key;
                    memcpy(kextName, value_key, key_len);
                    kextName[key_len] = 0;

                    if (strcmp(kextName, bundle_name) == 0) {
                        char* size_key = strstr(last_dict, "_PrelinkExecutableSize");
                        if (size_key != NULL) {
                            return plist_parse_integer(size_key);
                        }
                    }
                }
            }
        }

        last_dict = strstr(dict_end, "<dict>");
    }

    return 0;
}
