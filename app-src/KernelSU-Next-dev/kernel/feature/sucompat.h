#ifndef __XFG_H_SUCOMPAT
#define __XFG_H_SUCOMPAT
#include <asm/ptrace.h>
#include <linux/types.h>

extern bool xfg_su_compat_enabled;

void xfg_sucompat_init(void);
void xfg_sucompat_exit(void);

// Handler functions exported for hook_manager
long xfg_handle_faccessat_sucompat(int orig_nr, struct pt_regs *regs);
long xfg_handle_stat_sucompat(int orig_nr, struct pt_regs *regs);
long xfg_handle_execve_sucompat(const char __user **filename_user, int orig_nr, struct pt_regs *regs);
long xfg_handle_execveat_sucompat(const char __user **filename_user, int orig_nr, struct pt_regs *regs);

#endif
