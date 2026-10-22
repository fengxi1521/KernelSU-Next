#ifndef __XFG_H_XFGD
#define __XFG_H_XFGD

#include <asm/syscall.h>

#define XFGD_PATH "/data/adb/xfgd"

void xfg_xfgd_init();
void xfg_xfgd_exit();

void xfg_execve_hook_xfgd(const struct pt_regs *regs);
void xfg_execveat_hook_xfgd(const struct pt_regs *regs);
void xfg_stop_input_hook_runtime(void);

#endif
