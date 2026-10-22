#ifndef __XFG_H_ADB_ROOT
#define __XFG_H_ADB_ROOT
#include <asm/ptrace.h>

long xfg_adb_root_handle_execve(struct pt_regs *regs);
long xfg_adb_root_handle_execveat(struct pt_regs *regs);

void xfg_adb_root_init(void);

void xfg_adb_root_exit(void);

#endif
