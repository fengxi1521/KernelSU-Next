#ifndef __XFG_H_HOOK_MANAGER
#define __XFG_H_HOOK_MANAGER

#include <asm/ptrace.h>

// Hook manager initialization and cleanup
void xfg_syscall_hook_manager_init(void);
void xfg_syscall_hook_manager_exit(void);

// extras.c
void __init xfg_avc_spoof_init(void);
void __exit xfg_avc_spoof_exit(void);

#endif
