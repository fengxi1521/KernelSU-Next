#ifndef __XFG_H_XFG_CORE
#define __XFG_H_XFG_CORE

#include <linux/init.h>
#include <linux/types.h>

void xfg_setuid_hook_init(void);
void xfg_setuid_hook_exit(void);

// Handler functions for hook_manager
int xfg_handle_setresuid(uid_t old_uid, uid_t new_uid);

#endif
