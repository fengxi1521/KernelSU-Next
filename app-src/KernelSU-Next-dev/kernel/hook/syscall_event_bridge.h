#ifndef __XFG_H_SYSCALL_EVENT_BRIDGE
#define __XFG_H_SYSCALL_EVENT_BRIDGE

#include <asm/ptrace.h>

long xfg_hook_newfstatat(int orig_nr, const struct pt_regs *regs);
long xfg_hook_faccessat(int orig_nr, const struct pt_regs *regs);
long xfg_hook_execve(int orig_nr, const struct pt_regs *regs);
long xfg_hook_execveat(int orig_nr, const struct pt_regs *regs);
long xfg_hook_setresuid(int orig_nr, const struct pt_regs *regs);

void xfg_stop_xfgd_execve_hook(void);

#endif // __XFG_H_SYSCALL_EVENT_BRIDGE
