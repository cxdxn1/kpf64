#ifndef amfi_h
#define amfi_h

#define RET_INSN_OPC 0xD65F03C0, 0xFFFFFFFF

int kernel_patch_amfiret(void);

#endif /* amfi_h */