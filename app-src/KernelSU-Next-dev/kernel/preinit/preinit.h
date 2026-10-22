#ifndef __XFG_H_PREINIT
#define __XFG_H_PREINIT

#include <linux/types.h>
#include <asm/ptrace.h>

#ifndef XFG_NO_PREINIT
void xfg_preinit_init(void);
void xfg_preinit_exit(void);

// Swap the runner in for PID 1's "/system/bin/init selinux_setup" execve.
// Returns true when it issued the syscall itself; the result is in *ret.
bool xfg_preinit_handle_execve(const char __user **filename_user, const char __user *const __user *argv_user,
                               int orig_nr, struct pt_regs *regs, long *ret);

// Drop the staged runner if selinux_setup was never seen.
void xfg_preinit_release(void);

// Whether the runner is built in and not disabled with preinit=0.
bool xfg_preinit_enabled_param(void);
#else
static inline void xfg_preinit_init(void)
{
}
static inline void xfg_preinit_exit(void)
{
}
static inline bool xfg_preinit_handle_execve(const char __user **filename_user,
                                             const char __user *const __user *argv_user, int orig_nr,
                                             struct pt_regs *regs, long *ret)
{
    return false;
}
static inline void xfg_preinit_release(void)
{
}
static inline bool xfg_preinit_enabled_param(void)
{
    return false;
}
#endif

#endif // __XFG_H_PREINIT
